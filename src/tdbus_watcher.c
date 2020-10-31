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
#include "tdbus_watcher.h"

struct tdbus_timeout_record {
	int timerfd;
	DBusTimeout *timeout;
};

struct tdbus_watch {
	struct DBusWatch *watch;
	struct DBusTimeout *timeout;
	struct tdbus *bus;
};

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
	struct tdbus_watch *w = dbus_malloc(sizeof(*w));

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

static dbus_bool_t
tdbus_add_timeout(DBusTimeout *timeout, void *data)
{
	//the mask is always readable.
	struct tdbus *bus = data;
	int interval = dbus_timeout_get_interval(timeout);
	bool enabled = dbus_timeout_get_enabled(timeout) == TRUE;

	if (!bus->add_timeout_cb)
		return FALSE;
	bus->add_timeout_cb(bus->watch_userdata, interval, enabled,
	                    bus, timeout);

	return TRUE;
}

static void
tdbus_remove_timeout(DBusTimeout *timeout, void *data)
{
	struct tdbus *bus = data;
	void *userdata = dbus_timeout_get_data(timeout);

	if (!bus->rm_timeout_cb)
		return;
	bus->rm_timeout_cb(userdata, bus, timeout);
}

static void
tdbus_toggle_timeout(DBusTimeout *timeout, void *data)
{
	struct tdbus *bus = data;
	void *userdata = dbus_timeout_get_data(timeout);
	int interval = dbus_timeout_get_interval(timeout);

	if (dbus_timeout_get_enabled(timeout))
		bus->ch_timeout_cb(userdata, interval, bus, timeout);
}

TDBUS_EXPORT void
tdbus_watch_set_user_data(void *watch_data, void *user_data)
{
	dbus_watch_set_data(watch_data, user_data, NULL);
}

TDBUS_EXPORT void *
tdbus_watch_get_user_data(void *watch_data)
{
	return dbus_watch_get_data(watch_data);
}

TDBUS_EXPORT void
tdbus_timeout_set_user_data(void *timeout_data, void *user_data)
{
	dbus_timeout_set_data(timeout_data, user_data, NULL);
}

TDBUS_EXPORT void *
tdbus_timeout_get_user_data(void *timeout_data)
{
	return dbus_timeout_get_data(timeout_data);
}

TDBUS_EXPORT int
tdbus_timeout_gen_timerfd(void *timeout)
{
	int fd;
	int64_t interval;
	struct itimerspec timespec = {
		{0,0},
		{0,0},
	};

	//otherwise, create a timerfd to watch
	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (!fd)
		return -1;
	//initially disalarm the timer
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
	return fd;
err_settime:
	close(fd);
	return -1;
}

TDBUS_EXPORT void
tdbus_timeout_reset_timer(void *timeout, int timerfd)
{
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

TDBUS_EXPORT void
tdbus_handle_timeout(void *timeout_data)
{
	if (dbus_timeout_get_enabled(timeout_data))
		dbus_timeout_handle(timeout_data);
}

TDBUS_EXPORT void
tdbus_handle_watch(void *data)
{
	DBusWatch *watch = data;

	 if (dbus_watch_get_enabled(watch))
		 dbus_watch_handle(watch, dbus_watch_get_flags(watch));
}

TDBUS_EXPORT void
tdbus_set_nonblock(struct tdbus *bus, void *data,
                   tdbus_add_watch_f addf,
                   tdbus_ch_watch_f chf,
                   tdbus_rm_watch_f rmf,
                   tdbus_add_timeout_f addt,
                   tdbus_ch_timeout_f cht,
                   tdbus_rm_timeout_f rmt)
{
	dbus_bool_t r;

	bus->add_watch_cb = addf;
	bus->ch_watch_cb = chf;
	bus->rm_watch_cb = rmf;
	bus->add_timeout_cb = addt;
	bus->ch_timeout_cb = cht;
	bus->rm_timeout_cb = rmt;
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
	bus->add_timeout_cb = NULL;
	bus->ch_timeout_cb = NULL;
	bus->rm_timeout_cb = NULL;
	bus->non_block = false;
	bus->watch_userdata = NULL;
}
