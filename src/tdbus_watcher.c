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
void
tdbus_release_timeouts(struct tdbus *bus)
{
	struct tdbus_timeout_record *rec;
	void *userdata;

	if (bus->rm_watch_cb) {
		tdbus_array_for_each(rec, &bus->added_timeouts) {
			if (rec->timerfd > 0 && rec->timeout) {
				userdata = dbus_timeout_get_data(rec->timeout);
				bus->rm_watch_cb(userdata, rec->timerfd, bus,
				                 rec->timeout);
			}
		}
	}

	tdbus_array_release(&bus->added_timeouts);
}

static bool
tdbus_add_timeout_record(struct tdbus *bus, int timerfd, DBusTimeout *timeout)
{
	struct tdbus_timeout_record record, *copy;

	record.timeout = timeout;
	record.timerfd = timerfd;

	// search if there is any empty slots
	tdbus_array_for_each(copy, &bus->added_timeouts) {
		if (!copy->timeout || copy->timerfd < 0) { //emtpy
			copy->timeout = timeout;
			copy->timerfd = timerfd;
			return true;
		}
	}

	copy = tdbus_array_add(&bus->added_timeouts, sizeof(record));
	if (!copy)
		return false;
	*copy = record;

	return true;
}

static int
tdbus_find_timeout_fd(struct tdbus *bus, DBusTimeout *timeout)
{
	struct tdbus_timeout_record *rec;

	tdbus_array_for_each(rec, &bus->added_timeouts) {
		if (rec->timeout == timeout)
			return rec->timerfd;
	}

	return -1;
}

static void
tdbus_rm_timeout_record(struct tdbus *bus, int timerfd)
{
	struct tdbus_timeout_record *rec;

	tdbus_array_for_each(rec, &bus->added_timeouts) {
		if (rec->timerfd == timerfd) {
			rec->timerfd = -1;
			rec->timeout = NULL;
		}
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
