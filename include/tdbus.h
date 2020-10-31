/*
 * dbus.h - tdbus headers
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

#ifndef TDBUS_H
#define TDBUS_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>

#include "tdbus_message.h"
#include "tdbus_watcher.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tdbus;
struct tdbus_message;

enum TDBUS_TYPE {
	SYSTEM_BUS,
	SESSION_BUS,
};

enum tdbus_event_mask {
	TDBUS_READABLE = 1 << 0,
	TDBUS_WRITABLE = 1 << 1,
	TDBUS_ENABLED = 1 << 2,
};



struct tdbus *
tdbus_new(enum TDBUS_TYPE type);

struct tdbus *
tdbus_new_server(enum TDBUS_TYPE, const char *bus_name);

void
tdbus_delete(struct tdbus *bus);

bool
tdbus_match_signal(struct tdbus *bus,const char *sender,
                   const char *iface, const char *member,
                   const char *path, void *user_data,
                   tdbus_read_signal_f read_signal);
/**
 * @brief adding methods and register the object path
 */
bool
tdbus_server_add_methods(struct tdbus *bus, const char *obj_path,
                         unsigned int n_methods,
                         struct tdbus_call_answer *answers);

#ifdef __cplusplus
}
#endif

#endif /* EOF */
