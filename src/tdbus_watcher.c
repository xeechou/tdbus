/*
 * tdbus_watcher.c - tdbus watchers implementation
 *
 * Copyright (c) 2020 Xichen Zhou
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <dbus/dbus.h>

#include <tdbus.h>
#include "tdbus_internal.h"

struct tdbus_timeout_record {
	int timerfd;
	DBusTimeout *timeout;
};

static void tdbus_dispatch_timeout(void *data, int fd, DBusTimeout *timeout,
                                   struct tdbus *bus);

static int tdbus_find_timeout_fd(struct tdbus *bus, DBusTimeout *timeout);


static void
tdbus_toggle_watch(DBusWatch *watch, void *data)
{
	struct tdbus *bus = data;
	uint32_t mask = 0, flags;
	int fd;

	if (!bus->ch_watch_cb)
		return;

	fd = dbus_watch_get_unix_fd(watch);
	if (dbus_watch_get_enabled(watch)) {
		mask |= TDBUS_ENABLED;
		flags = dbus_watch_get_flags(watch);
		if (flags & DBUS_WATCH_READABLE)
			mask |= TDBUS_READABLE;
		if (flags & DBUS_WATCH_WRITABLE)
			mask |= TDBUS_WRITABLE;
	}
	bus->ch_watch_cb(bus->watch_userdata, fd, bus, mask, watch);
}

static dbus_bool_t
tdbus_add_watch(DBusWatch *watch, void *data)
{
	struct tdbus *bus = data;
	int fd;
	uint32_t mask = 0, flags;

	//there is nothing we can do here
	if (!bus->add_watch_cb)
		return FALSE;
	if (dbus_watch_get_enabled(watch)) {
		mask |= TDBUS_ENABLED;
		flags = dbus_watch_get_flags(watch);
		if (flags & DBUS_WATCH_READABLE)
			mask |= TDBUS_READABLE;
		if (flags & DBUS_WATCH_WRITABLE)
			mask |= TDBUS_WRITABLE;
	}
	fd = dbus_watch_get_unix_fd(watch);
	//In this callback we need to register this fd as some event callback
	bus->add_watch_cb(bus->watch_userdata, fd, bus, mask, watch);

	return TRUE;
}

static void
tdbus_remove_watch(DBusWatch *watch, void *data)
{
	struct tdbus *bus = data;
	int fd;

	if (!bus->rm_watch_cb)
		return;

	fd = dbus_watch_get_unix_fd(watch);
	bus->rm_watch_cb(bus->watch_userdata, fd, bus, watch);
}

void
tdbus_handle_watch(struct tdbus *bus, void *data)
{
	DBusTimeout *timeout = data;
	DBusWatch *watch = data;
	int timerfd = tdbus_find_timeout_fd(bus, timeout);

	if (timerfd > 0)
		tdbus_dispatch_timeout(data, timerfd, timeout, bus);
	else if (dbus_watch_get_enabled(watch))
		dbus_watch_handle(watch,
		                  dbus_watch_get_flags(watch));
}

/*******************************************************************************
 * dbus timeouts
 ******************************************************************************/
bool
tdbus_init_timeouts(struct tdbus *bus)
{
	struct tdbus_timeout_record *records =
		malloc(sizeof(struct tdbus_timeout_record) * 16);
	if (!records)
		return false;
	//set records to -1 so they are invalid
	memset(records, -1, sizeof(struct tdbus_timeout_record) * 16);
	bus->timeouts = records;
	bus->timeouts_used = 0;
	bus->timeouts_allocated = 16;
	return true;
}

void
tdbus_release_timeouts(struct tdbus *bus)
{
	if (bus->timeouts) {
		free(bus->timeouts);
		bus->timeouts_allocated = 0;
		bus->timeouts_used = 0;
	}
}

static bool
tdbus_add_timeout_record(struct tdbus *bus, int timerfd, DBusTimeout *timeout)
{
	//test if there is still slots inside
	if (bus->timeouts_used < bus->timeouts_allocated)
		goto insert_timeout;

	size_t new_size = bus->timeouts_allocated  * 2 *
		sizeof(struct tdbus_timeout_record);
	int counter = 0;

	struct tdbus_timeout_record *new_records =
		bus->timeouts;
	if ((new_records = realloc(bus->timeouts, new_size)) == NULL)
		return false;

	for (unsigned i = 0; i < bus->timeouts_used; i++) {
		struct tdbus_timeout_record *old_rec =
			bus->timeouts + i;
		struct tdbus_timeout_record *new_rec =
			new_records + counter;
		struct tdbus_timeout_record tmp = *old_rec;

		if (tmp.timerfd > 0 && tmp.timeout) {
			*new_rec  = tmp;
			counter++;
		}
	}
	bus->timeouts = new_records;
	bus->timeouts_used = counter;
	bus->timeouts_allocated *= 2;

insert_timeout:
	new_records = bus->timeouts + bus->timeouts_used;
	new_records->timeout = timeout;
	new_records->timerfd = timerfd;
	bus->timeouts_used += 1;

	return true;
}

static int
tdbus_find_timeout_fd(struct tdbus *bus, DBusTimeout *timeout)
{
	for (unsigned i = 0; i < bus->timeouts_used; i++)
		if ((bus->timeouts + i)->timeout == timeout)
			return (bus->timeouts + i)->timerfd;
	return 0;
}

static void
tdbus_rm_timeout_record(struct tdbus *bus, int timerfd)
{
	for (unsigned i = 0; i < bus->timeouts_used; i++)
		if ((bus->timeouts + i)->timerfd == timerfd) {
			(bus->timeouts+i)->timerfd = -1;
			(bus->timeouts+i)->timeout = NULL;
			break;
		}
}

static dbus_bool_t
tdbus_add_timeout(DBusTimeout *timeout, void *data)
{
	struct tdbus *bus = data;
	int64_t interval;
	int fd;
	struct itimerspec timespec = {
		{0,0},
		{0,0},
	};

	if (!bus->add_watch_cb)
		goto err_init_timer;
	//otherwise, create a timerfd to watch
	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (!fd)
		goto err_init_timer;
	if (timerfd_settime(fd, 0, &timespec, NULL))
		goto err_settime;

	if (dbus_timeout_get_enabled(timeout)) {
		interval = dbus_timeout_get_interval(timeout);
		timespec.it_value.tv_nsec = interval * 1000;
		timespec.it_value.tv_sec = 0;
		timespec.it_interval = timespec.it_value;

		if (timerfd_settime(fd, 0, &timespec, NULL))
			goto err_settime;
	}

	bus->add_watch_cb(bus->watch_userdata, fd, bus,
	                  TDBUS_READABLE, timeout);
	tdbus_add_timeout_record(bus, fd, timeout);
	dbus_timeout_set_data(timeout, bus->watch_userdata, NULL);

	return TRUE;
err_settime:
	close(fd);
err_init_timer:
	return FALSE;
}

static void
tdbus_remove_timeout(DBusTimeout *timeout, void *data)
{
	struct tdbus *bus = data;
	void *userdata = dbus_timeout_get_data(timeout);
	int timerfd = tdbus_find_timeout_fd(bus, timeout);

	if (!bus->rm_watch_cb)
		return;

	bus->rm_watch_cb(userdata, timerfd, bus, timeout);
	tdbus_rm_timeout_record(bus, timerfd);
}

static void
tdbus_toggle_timeout(DBusTimeout *timeout, void *data)
{
	struct tdbus *bus = data;
	int timerfd = tdbus_find_timeout_fd(bus, timeout);

	if (dbus_timeout_get_enabled(timeout)) {
		int64_t interval = dbus_timeout_get_interval(timeout);
		struct itimerspec timespec = {
			.it_value = {
				.tv_sec = 0,
				.tv_nsec = interval * 1000,
			},
			.it_interval = {
				.tv_sec = 0,
				.tv_nsec = interval * 1000,
			},
		};
		timerfd_settime(timerfd, 0, &timespec, NULL);
	}

}

static void
tdbus_dispatch_timeout(void *data, int timerfd, DBusTimeout *timeout,
                       struct tdbus *bus)
{
	uint64_t nhit;
	//read the timer first
	read(timerfd, &nhit, 8);
	//find the timer based on fd
	if (timeout && dbus_timeout_get_enabled(timeout))
		dbus_timeout_handle(timeout);
}

void
tdbus_watch_set_user_data(void *watch_data, void *user_data)
{
	dbus_watch_set_data(watch_data, user_data, NULL);
}

void *
tdbus_watch_get_user_data(void *watch_data)
{
	return dbus_watch_get_data(watch_data);
}

void
tdbus_set_nonblock(struct tdbus *bus, void *data,
                   tdbus_add_watch_f addf,
                   tdbus_ch_watch_f chf,
                   tdbus_rm_watch_f rmf)
{
	dbus_bool_t r;

	bus->add_watch_cb = addf;
	bus->ch_watch_cb = chf;
	bus->rm_watch_cb = rmf;
	bus->non_block = true;
	bus->watch_userdata = data;

	r = dbus_connection_set_watch_functions(bus->conn,
	                                        tdbus_add_watch,
	                                        tdbus_remove_watch,
	                                        tdbus_toggle_watch,
	                                        bus,
	                                        NULL);
	if (r != TRUE)
		goto err_set_func;
	r = dbus_connection_set_timeout_functions(bus->conn,
	                                          tdbus_add_timeout,
	                                          tdbus_remove_timeout,
	                                          tdbus_toggle_timeout,
	                                          bus,
	                                          NULL);
	if (r != TRUE)
		goto err_set_func;
	return;

err_set_func:
	dbus_connection_set_watch_functions(bus->conn, NULL, NULL,
	                                    NULL, NULL, NULL);
	dbus_connection_set_timeout_functions(bus->conn, NULL, NULL,
	                                      NULL, NULL, NULL);
	bus->add_watch_cb = NULL;
	bus->ch_watch_cb = NULL;
	bus->rm_watch_cb = NULL;
	bus->non_block = false;
	bus->watch_userdata = NULL;
}
