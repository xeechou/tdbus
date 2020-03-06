/*
 * tdbus_internal.h - internal use data types
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

#ifndef TDBUS_INTERNAL_H
#define TDBUS_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <dbus/dbus.h>

#include <tdbus.h>

#ifdef __cplusplus
extern "C" {
#endif

struct tdbus_timeout_record;
struct tdbus_method_record;

/*
 * the only use of bus message right now is the reply
 */
struct tdbus_message {
	struct tdbus *bus;
	DBusMessage *message;
	tdbus_read_reply_f read_reply;
	void *user_data;
};

struct tdbus {
	//I dont know that is inside
	struct DBusConnection *conn;
	char *service_name;
	bool non_block;

	/* watchers */
	tdbus_add_watch_f add_watch_cb;
	tdbus_rm_watch_f rm_watch_cb;
	tdbus_ch_watch_f ch_watch_cb;
	void *watch_userdata;
	/* timeouts */
	struct tdbus_timeout_record *timeouts;
	size_t timeouts_used,  timeouts_allocated;

	/* readers */
	tdbus_read_signal_f read_signal_cb;
	void *signal_userdata;
	tdbus_read_call_f read_method_cb;
	void *method_userdata;
	tdbus_read_reply_f read_reply_cb;
	void *reply_userdata;

	/* server data */
	struct {
		char objpath[32];
		size_t start;
		size_t n_methods;
	} registered_objs[8];

	int n_methods, n_method_alloc, n_objs;
	struct tdbus_method_record *method_records;
};

bool tdbus_init_timeouts(struct tdbus *bus);

void tdbus_release_timeouts(struct tdbus *bus);


void tdbus_reader_from_message(DBusMessage *message,
                               struct tdbus_signal *signal,
                               struct tdbus_method_call *call,
                               struct tdbus_reply *reply);


#ifdef __cplusplus
}
#endif

#endif /* EOF */
