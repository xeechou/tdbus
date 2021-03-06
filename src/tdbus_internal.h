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

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <dbus/dbus.h>

#include <tdbus.h>

/** Visibility */
#if defined(__GNUC__) && __GNUC__ >= 4
#define TDBUS_EXPORT __attribute__ ((visibility("default")))
#else
#define TDBUS_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct tdbus_timeout_record;
struct tdbus_method_record;
struct tdbus_signal_match;

/*
 * the only use of bus message right now is the reply
 */
struct tdbus_message {
	struct tdbus *bus;
	DBusMessage *message;
	tdbus_read_reply_f read_reply;
	void *user_data;
};

struct tdbus_array {
	/** Array size */
	size_t size;
	/** Allocated space */
	size_t alloc;
	/** Array data */
	void *data;
};

void tdbus_array_init(struct tdbus_array *array);

void tdbus_array_init_fixed(struct tdbus_array *array,
                            size_t alloc, void *data);

void tdbus_array_release(struct tdbus_array *array);

void *tdbus_array_add(struct tdbus_array *array, size_t size);

#define tdbus_array_for_each(pos, array)                                \
	for (pos = (array)->data; \
	     (const char *) pos < ((const char *) (array)->data + (array)->size); \
	     (pos)++)

struct tdbus {
	//I dont know that is inside
	struct DBusConnection *conn;
	char *service_name;
	bool non_block;
	tdbus_logger_fn logger;

	/* watchers */
	tdbus_add_watch_f add_watch_cb;
	tdbus_rm_watch_f rm_watch_cb;
	tdbus_ch_watch_f ch_watch_cb;
	void *watch_userdata;

	/* timeouts */
	tdbus_add_timeout_f add_timeout_cb;
	tdbus_ch_timeout_f ch_timeout_cb;
	tdbus_rm_timeout_f rm_timeout_cb;

	struct tdbus_array matched_signals;

	/* server data */
	int n_objs;
	struct {
		char objpath[32];
		size_t start;
		size_t n_methods;
	} registered_objs[8];

	struct tdbus_array added_methods;
};

void tdbus_release_methods(struct tdbus *bus);

void tdbus_reader_from_message(DBusMessage *message,
                               struct tdbus_signal *signal,
                               struct tdbus_method_call *call,
                               struct tdbus_reply *reply);

void tdbus_unmatch_signals(struct tdbus *bus);

DBusHandlerResult tdbus_handle_signal(struct tdbus *bus,
                                      struct tdbus_signal *signal);
static inline void
tdbus_log(struct tdbus *bus, enum tdbus_log_level level, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	if (bus->logger)
		bus->logger(level, fmt, args);
	va_end(args);
}

static inline bool
tdbus_handle_error(struct tdbus *bus, enum tdbus_log_level level,
                   const char *fn_name, const DBusError *err)
{
	bool pass = true;
	const char *fmt = "%s failed with error message: %s:%s";
	if (dbus_error_is_set(err)) {
		pass = false;
		tdbus_log(bus, level, fmt, fn_name, err->name, err->message);
	}
	return pass;
}

#ifdef __cplusplus
}
#endif

#endif /* EOF */
