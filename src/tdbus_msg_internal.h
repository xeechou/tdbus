/*
 * tdbus_msg_internal.h - internal message internal header
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

#ifndef TDBUS_MSG_INTERNAL_H
#define TDBUS_MSG_INTERNAL_H

#include "tdbus_message_iter.h"
#include "tdbus_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _tdbus_message_itr {
	struct tdbus_message_itr it;
	struct tdbus_array arr;
};


static inline enum tdbus_arg_type
tdbus_arg_type_from_dbus(int dbus_type)
{
	switch (dbus_type) {
	case DBUS_TYPE_BOOLEAN:
		return TDBUS_ARG_BOOLEAN;
	case DBUS_TYPE_BYTE:
		return TDBUS_ARG_BYTE;
	case DBUS_TYPE_STRING:
		return TDBUS_ARG_STRING;
	case DBUS_TYPE_OBJECT_PATH:
		return TDBUS_ARG_OBJPATH;
	case DBUS_TYPE_UNIX_FD:
		return TDBUS_ARG_FD;
	case DBUS_TYPE_INT16:
		return TDBUS_ARG_INT16;
	case DBUS_TYPE_INT32:
		return TDBUS_ARG_INT32;
	case DBUS_TYPE_INT64:
		return TDBUS_ARG_INT64;
	case DBUS_TYPE_UINT16:
		return TDBUS_ARG_UINT16;
	case DBUS_TYPE_UINT32:
		return TDBUS_ARG_UINT32;
	case DBUS_TYPE_UINT64:
		return TDBUS_ARG_UINT64;
	case DBUS_TYPE_DOUBLE:
		return TDBUS_ARG_DOUBLE;
	case DBUS_TYPE_ARRAY:
		return TDBUS_ARG_ARRAY;
	case DBUS_TYPE_STRUCT:
		return TDBUS_ARG_STRUCT;
	default:
		return TDBUS_ARG_UNKNOWN;
	}
}

static inline size_t
tdbus_get_msg_arg_size(int code)
{
	switch (code) {
	case DBUS_TYPE_BYTE:
		return sizeof(char);
	case DBUS_TYPE_BOOLEAN:
		return sizeof(dbus_bool_t);
	case DBUS_TYPE_UNIX_FD:
		return sizeof(int);

	case DBUS_TYPE_INT16: //signed int
		return sizeof(int16_t);
	case DBUS_TYPE_INT32:
		return sizeof(int32_t);
	case DBUS_TYPE_INT64:
		return sizeof(int64_t);

	case DBUS_TYPE_UINT16: //unsigned int
		return sizeof(uint16_t);
	case DBUS_TYPE_UINT32:
		return sizeof(uint32_t);
	case DBUS_TYPE_UINT64:
		return sizeof(uint64_t);

	case DBUS_TYPE_DOUBLE:
		return sizeof(double);
	case DBUS_TYPE_OBJECT_PATH:
	case DBUS_TYPE_STRING:
		return sizeof(char *);
	default:
		return 0;
	}

}


#define tdbus_container_of(ptr, type, member)                           \
	({ \
		const __typeof__(((type *)0)->member) *__mptr = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); \
	})



#ifdef __cplusplus
}
#endif


#endif /* EOF */
