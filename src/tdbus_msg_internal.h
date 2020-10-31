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

#include <dbus/dbus.h>
#include "tdbus_message_iter.h"
#include "tdbus_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

struct _tdbus_message_itr {
	struct tdbus_message_itr it;
	struct tdbus_array arr;
};

void
_tdbus_message_itr_init(struct _tdbus_message_itr *itr,
                        struct tdbus_message_arg *value);

#define tdbus_container_of(ptr, type, member)                           \
	({ \
		const __typeof__(((type *)0)->member) *__mptr = (ptr); \
		(type *)((char *)__mptr - offsetof(type, member)); \
	})

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
	case DBUS_TYPE_SIGNATURE:
		return TDBUS_ARG_SIG;
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
	case DBUS_TYPE_DICT_ENTRY:
		return TDBUS_ARG_DICT_ENTRY;
	case DBUS_TYPE_VARIANT:
		return TDBUS_ARG_VARIANT;
	case DBUS_TYPE_STRUCT:
		return TDBUS_ARG_STRUCT;
	default:
		return TDBUS_ARG_UNKNOWN;
	}
}

static inline int
tdbus_arg_type_to_dbus(enum tdbus_arg_type type)
{
	switch (type) {
	case TDBUS_ARG_BYTE:
		return DBUS_TYPE_BYTE;
	case TDBUS_ARG_BOOLEAN:
		return DBUS_TYPE_BOOLEAN;
	case TDBUS_ARG_FD:
		return DBUS_TYPE_UNIX_FD;

	case TDBUS_ARG_INT16: //signed int
		return DBUS_TYPE_INT16;
	case TDBUS_ARG_INT32:
		return DBUS_TYPE_INT32;
	case TDBUS_ARG_INT64:
		return DBUS_TYPE_INT64;

	case TDBUS_ARG_UINT16: //unsigned int
		return DBUS_TYPE_UINT16;
	case TDBUS_ARG_UINT32:
		return DBUS_TYPE_UINT32;
	case TDBUS_ARG_UINT64:
		return DBUS_TYPE_UINT64;

	case TDBUS_ARG_DOUBLE:
		return DBUS_TYPE_DOUBLE;
	case TDBUS_ARG_OBJPATH:
		return DBUS_TYPE_OBJECT_PATH;
	case TDBUS_ARG_STRING:
		return DBUS_TYPE_STRING;
	case TDBUS_ARG_SIG:
		return DBUS_TYPE_SIGNATURE;
		//the object types would requires tdbus_message_arg
	case TDBUS_ARG_VARIANT:
		return DBUS_TYPE_VARIANT;
	case TDBUS_ARG_ARRAY:
		return DBUS_TYPE_ARRAY;
	case TDBUS_ARG_STRUCT:
		return DBUS_TYPE_STRUCT;
	case TDBUS_ARG_DICT_ENTRY:
		return DBUS_TYPE_DICT_ENTRY;

	default:
		return 0;
	}

}

static inline size_t
tdbus_get_msg_arg_size(enum tdbus_arg_type type)
{
	switch (type) {
	case TDBUS_ARG_BYTE:
		return sizeof(char);
	case TDBUS_ARG_BOOLEAN:
		return sizeof(dbus_bool_t);
	case TDBUS_ARG_FD:
		return sizeof(int);

	case TDBUS_ARG_INT16: //signed int
		return sizeof(int16_t);
	case TDBUS_ARG_INT32:
		return sizeof(int32_t);
	case TDBUS_ARG_INT64:
		return sizeof(int64_t);

	case TDBUS_ARG_UINT16: //unsigned int
		return sizeof(uint16_t);
	case TDBUS_ARG_UINT32:
		return sizeof(uint32_t);
	case TDBUS_ARG_UINT64:
		return sizeof(uint64_t);

	case TDBUS_ARG_DOUBLE:
		return sizeof(double);
	case TDBUS_ARG_OBJPATH:
	case TDBUS_ARG_STRING:
	case TDBUS_ARG_SIG:
		return sizeof(char *);
		//the object types would requires tdbus_message_arg
	case TDBUS_ARG_VARIANT:
	case TDBUS_ARG_ARRAY:
	case TDBUS_ARG_STRUCT:
		return sizeof(struct tdbus_message_arg);
	case TDBUS_ARG_DICT_ENTRY:
		return sizeof(struct tdbus_arg_dict_entry);

	default:
		return 0;
	}
}

static inline bool
tdbus_type_is_string(enum tdbus_arg_type type)
{
	return type == TDBUS_ARG_STRING ||
		type == TDBUS_ARG_OBJPATH ||
		type == TDBUS_ARG_SIG;
}

static inline bool
tdbus_type_is_object(enum tdbus_arg_type type)
{
	return type == TDBUS_ARG_ARRAY ||
		type == TDBUS_ARG_STRUCT ||
		type == TDBUS_ARG_VARIANT;
}

static inline bool
tdbus_type_is_dict_entry(enum tdbus_arg_type type)
{
	return type == TDBUS_ARG_DICT_ENTRY;
}

static inline bool
tdbus_type_is_fixed(enum tdbus_arg_type type)
{
	switch (type) {
	case TDBUS_ARG_BYTE:
	case TDBUS_ARG_BOOLEAN:
	case TDBUS_ARG_FD:
	case TDBUS_ARG_INT16:
	case TDBUS_ARG_INT32:
	case TDBUS_ARG_INT64:
	case TDBUS_ARG_UINT16:
	case TDBUS_ARG_UINT32:
	case TDBUS_ARG_UINT64:
	case TDBUS_ARG_DOUBLE:
		return true;
	default:
		return false;
	}
}

#ifdef __cplusplus
}
#endif


#endif /* EOF */
