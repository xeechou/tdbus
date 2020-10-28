/*
 * tdbus_msg_read.c - tdbus message reader implementation
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
#include <dbus/dbus.h>
#include <dbus/dbus-protocol.h>

#include <tdbus.h>
#include "tdbus_msg_internal.h"
#include "tdbus_message_iter.h"


static struct tdbus_message_arg *
_tdbus_msg_itr_next(struct tdbus_message_itr *itr, int dbus_type)
{
	struct _tdbus_message_itr *_itr =
		tdbus_container_of(itr, struct _tdbus_message_itr, it);
	struct tdbus_message_arg *arg;
	size_t curr_size = itr->curr * sizeof(struct tdbus_message_arg);
	size_t size = (itr->curr+1) * sizeof(struct tdbus_message_arg);

	if ( size < _itr->arr.alloc) {
		arg = (struct tdbus_message_arg *)
			((char *)_itr->arr.data + curr_size);
		_itr->arr.size += sizeof(struct tdbus_message_arg);
	} else {
		arg = tdbus_array_add(&_itr->arr,
		                      sizeof(struct tdbus_message_arg));
		if (!arg)
			return NULL;
		arg->type = tdbus_arg_type_from_dbus(dbus_type);
		itr->args = _itr->arr.data;
	}

	itr->curr += 1;
	return arg;
}

#define tdbus_msg_itr_next(itr, type, dbus_type)                        \
	(!itr->args) ? va_arg(itr->va, type) \
	: (type)_tdbus_msg_itr_next(itr, dbus_type)

static DBusBasicValue *
tdbus_msg_itr_get_arr(struct tdbus_message_itr *itr, int type, int count)
{
	DBusBasicValue **value_ptr, *value;
	struct tdbus_message_arg *curr;

	value = malloc(count * tdbus_get_msg_arg_size(type));
	if (!value)
		return NULL;

	if (!itr->args) {
		*va_arg(itr->va, int *) = count;
		value_ptr = va_arg(itr->va,  DBusBasicValue**);
		*value_ptr = value;
	} else {
		curr = _tdbus_msg_itr_next(itr, type);
		curr->type = TDBUS_ARG_ARRAY;
		curr->arg.arr.n = count;
		curr->arg.arr.type = tdbus_arg_type_from_dbus(type);
		curr->arg.arr.a = value;
	}
	return value;
}

/******************************************************************************
 * tdbus_reader
 *****************************************************************************/

bool tdbus_read_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
                    struct tdbus_message_itr *mitr);

static bool
tdbus_read_array(DBusSignatureIter *sitr, DBusMessageIter *itr,
                 struct tdbus_message_itr *mitr)
{
	int count, basic_type, size;
	void *arr_ptr;
	DBusBasicValue *value, basic_value;
	DBusMessageIter sub_itr;
	DBusSignatureIter sub_sitr;

	dbus_message_iter_recurse(itr, &sub_itr);
	dbus_signature_iter_recurse(sitr, &sub_sitr);
	basic_type = dbus_message_iter_get_arg_type(&sub_itr);

	if (dbus_signature_iter_get_element_type(sitr) != basic_type ||
	    !dbus_type_is_basic(basic_type))
		return false;

	count = dbus_message_iter_get_element_count(itr);
	size = count * tdbus_get_msg_arg_size(basic_type);
        if (size <= 0)
		return false;

        value = tdbus_msg_itr_get_arr(mitr, basic_type, count);
        if (!value)
	        return false;

	if (dbus_type_is_fixed(basic_type)) {
	        dbus_message_iter_get_fixed_array(&sub_itr, &arr_ptr, &count);
	        //asign values back
	        memcpy(value, arr_ptr, size);
	} else { //this must be a string, which was the longest type
		for (int i = 0; i < count; i++) {
			dbus_message_iter_get_basic(&sub_itr, &basic_value);
			value[i].str = strdup(basic_value.str);
			dbus_message_iter_next(&sub_itr);
		}
        }

	return true;
}

static bool
tdbus_read_struct(DBusSignatureIter *sitr, DBusMessageIter *itr,
                  struct tdbus_message_itr *mitr)
{
	DBusMessageIter sub_iter;
	DBusSignatureIter sub_siter;
	struct tdbus_message_itr sub_mitr = {0}, *_sub_mitr;
	struct tdbus_message_arg *arg;

	if (!mitr->args) {
		va_copy(sub_mitr.va, mitr->va);
		_sub_mitr = &sub_mitr;
	} else {
		arg = _tdbus_msg_itr_next(mitr, DBUS_TYPE_STRUCT);
		arg->type = TDBUS_ARG_STRUCT;
		arg->arg.st = tdbus_msg_itr_new();
		if (!arg->arg.st)
			return false;
		_sub_mitr = arg->arg.st;
	}
	if (!mitr->args) {
		va_end(mitr->va);
		va_copy(mitr->va, sub_mitr.va);
		va_end(sub_mitr.va);
	}

	dbus_message_iter_recurse(itr, &sub_iter);
	dbus_signature_iter_recurse(sitr, &sub_siter);
	return tdbus_read_itr(&sub_siter, &sub_iter, _sub_mitr);
}

static bool
tdbus_read_basic(DBusSignatureIter *sitr, DBusMessageIter *itr,
                 struct tdbus_message_itr *mitr)
{
	int type = dbus_message_iter_get_arg_type(itr);
	DBusBasicValue value;

	if (type != dbus_signature_iter_get_current_type(sitr))
		return false;

	dbus_message_iter_get_basic(itr, &value);

	switch (type) {
	case DBUS_TYPE_BYTE:
		*(char *)(tdbus_msg_itr_next(mitr, char *, type)) = value.byt;
		break;
	case DBUS_TYPE_BOOLEAN:
		*(bool *)(tdbus_msg_itr_next(mitr, bool *, type)) =
			value.bool_val;
		break;
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		*(char **)(tdbus_msg_itr_next(mitr, char **, type)) =
			strdup(value.str);
		break;

	case DBUS_TYPE_UNIX_FD:
		*(int *)(tdbus_msg_itr_next(mitr, int *, type)) = value.fd;
		break;

	case DBUS_TYPE_INT16: //signed int
		*(int16_t *)(tdbus_msg_itr_next(mitr, int16_t *, type)) =
			value.i16;
		break;
	case DBUS_TYPE_INT32:
		*(int32_t *)(tdbus_msg_itr_next(mitr, int32_t *, type)) =
			value.i32;
		break;
	case DBUS_TYPE_INT64:
		*(int64_t *)(tdbus_msg_itr_next(mitr, int64_t *, type)) =
			value.i64;
		break;

	case DBUS_TYPE_UINT16: //unsigned int
		*(uint16_t *)(tdbus_msg_itr_next(mitr, uint16_t *, type)) =
			value.u16;
		break;
	case DBUS_TYPE_UINT32:
		*(uint32_t *)(tdbus_msg_itr_next(mitr, uint32_t *, type)) =
			value.u32;
		break;
	case DBUS_TYPE_UINT64:
		*(uint64_t *)(tdbus_msg_itr_next(mitr, uint64_t *, type)) =
			value.u64;
		break;

	case DBUS_TYPE_DOUBLE:
		*(double *)(tdbus_msg_itr_next(mitr, double *, type)) =
			value.dbl;
		break;

	default: //impossible
		assert(0);
		break;
	}
	return true;
}

bool tdbus_read_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
                    struct tdbus_message_itr *mitr)
{
	int arg_type;
	int advance = 0;
	//mitr would auto increase

	while ((arg_type = dbus_message_iter_get_arg_type(itr)) !=
	       DBUS_TYPE_INVALID) {

		if (dbus_signature_iter_get_current_type(sitr) != arg_type)
			return false;

		if (arg_type == DBUS_TYPE_ARRAY) {
			if (!tdbus_read_array(sitr, itr, mitr))
				return false;
		} else if (arg_type == DBUS_TYPE_STRUCT) {
			if (!tdbus_read_struct(sitr, itr, mitr))
				return false;
		} else if (dbus_type_is_basic(arg_type)) {
			if (!tdbus_read_basic(sitr, itr, mitr))
				return false;
		} else //we don't deal with complex msg now
			return false;
		//do something?
		dbus_message_iter_next(itr);
		advance = dbus_signature_iter_next(sitr);
	}
	//actually testing if we are at the end
	if ((arg_type == DBUS_TYPE_INVALID) && (advance == 0))
		return true;
	else
		return false;
}

TDBUS_EXPORT void
tdbus_readv(const struct tdbus_message *msg, const char *format, va_list ap)
{
	struct tdbus_message_itr itr = {0};

	va_copy(itr.va, ap);
	tdbus_read_with_iter(msg, format, &itr);
	va_end(itr.va);
}

TDBUS_EXPORT bool
tdbus_read_with_iter(const struct tdbus_message *msg, const char *format,
                     struct tdbus_message_itr *itr)
{
	DBusMessageIter iter;
	DBusSignatureIter sig_itr;
	DBusMessage *message = msg->message;

        //now we go through the list of message
	//actually read the message
	if (dbus_signature_validate(format, NULL) != TRUE)
		return false;

	dbus_signature_iter_init(&sig_itr, format);
	dbus_message_iter_init(message, &iter);

	return tdbus_read_itr(&sig_itr, &iter, itr);
}
