/*
 * dbus_message_itr.h - tdbus message iter headers
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


#ifndef TDBUS_MESSAGE_ITER_H
#define TDBUS_MESSAGE_ITER_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

union tdbus_arg_value;
struct tdbus_message_arg;

enum tdbus_arg_type {
	TDBUS_ARG_BYTE,
	TDBUS_ARG_BOOLEAN,
	TDBUS_ARG_STRING,
	TDBUS_ARG_OBJPATH,
	TDBUS_ARG_SIG,
	TDBUS_ARG_FD,
	TDBUS_ARG_INT16,
	TDBUS_ARG_INT32,
	TDBUS_ARG_INT64,
	TDBUS_ARG_UINT16,
	TDBUS_ARG_UINT32,
	TDBUS_ARG_UINT64,
	TDBUS_ARG_DOUBLE,
	TDBUS_ARG_ARRAY,
	TDBUS_ARG_STRUCT,
	TDBUS_ARG_VARIANT,
	TDBUS_ARG_DICT_ENTRY, //dict entry can only be
	TDBUS_ARG_UNKNOWN,
};

struct tdbus_arg_variant {
	char signature[16];
	struct tdbus_message_arg *arg;
};

union tdbus_arg_value {
	unsigned char c;
	bool b;
	char *str;
	int fd;

	int16_t i16;
	int32_t i32;
	int64_t i64;

	uint16_t u16;
	uint32_t u32;
	uint64_t u64;

	double d;
	struct {
		enum tdbus_arg_type type;
		unsigned n;
		void *a;
	} arr;

	struct tdbus_arg_variant variant;
	//a dict entry will be a fix type inside an array.
	struct tdbus_arg_dict_entry *entry;
	//new struct
	struct tdbus_message_itr *st;
};

struct tdbus_message_arg {
	union tdbus_arg_value arg;
	enum tdbus_arg_type type;
};

struct tdbus_arg_dict_entry {
	struct tdbus_message_arg key, val;
};

struct tdbus_message_itr {
	va_list va;
	//The args here only used for testing
	struct tdbus_message_arg *args;
	size_t curr;
};

struct tdbus_message_itr *tdbus_msg_itr_new(void);

void tdbus_msg_itr_done(struct tdbus_message_itr *itr);

void
tdbus_msg_done_arg(struct tdbus_message_arg *arg);

/** free the variant (allocated from reading) resource */
void
tdbus_msg_done_variant(struct tdbus_message_arg *variant);

void
tdbus_msg_done_dict_entry(struct tdbus_arg_dict_entry *entry);

/** convenience function for deallocate array at once, behavior undefined if
 * wrong type is provided */
void
tdbus_msg_free_array(void *array, unsigned count, enum tdbus_arg_type type);

#ifdef __cplusplus
}
#endif


#endif /* EOF */
