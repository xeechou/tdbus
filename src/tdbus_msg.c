/*
 * tdbus_msg.c - tdbus message implementation
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

#include <dbus/dbus-protocol.h>
#include <dbus/dbus.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <tdbus.h>
#include "tdbus_internal.h"

bool tdbus_write_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
                     va_list ap);

bool tdbus_read_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
                    va_list ap);

static inline int
tdbus_get_msg_arg_basic_type(int code)
{
	switch (code) {
		case 'y':
			return DBUS_TYPE_BYTE;
		case 'b':
			return DBUS_TYPE_BOOLEAN;
		case 's':
			return DBUS_TYPE_STRING;
		case 'h':
			return DBUS_TYPE_UNIX_FD;

		case 'i': //signed int
			return DBUS_TYPE_INT16;
		case 'n':
			return DBUS_TYPE_INT32;
		case 'x':
			return DBUS_TYPE_INT64;

		case 'q': //unsigned int
			return DBUS_TYPE_UINT16;
		case 'u':
			return DBUS_TYPE_UINT32;
		case 't':
			return DBUS_TYPE_UINT64;

		case 'd':
			return DBUS_TYPE_DOUBLE;

		default:
			return DBUS_TYPE_INVALID;
	}
}

static inline int
tdbus_get_msg_arg_type(int code)
{
	if (code == 'a')
		return DBUS_TYPE_ARRAY;
	else if (code == '(')
		return DBUS_TYPE_STRUCT;
	else //does not deal with variant, variant is marshalled
		return tdbus_get_msg_arg_basic_type(code);
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

/**
 * right now we support only basica type arries
 */
static bool
tdbus_write_array(DBusSignatureIter *sitr, DBusMessageIter *itr,
                  int nelem, void *data)
{
	int basic_type;
	DBusMessageIter sub_itr;
	DBusBasicValue value;
	char *sub_signature;

	basic_type = dbus_signature_iter_get_element_type(sitr);

	if (!dbus_type_is_basic(basic_type))
		return false;

	sub_signature = dbus_signature_iter_get_signature(sitr);

	if (dbus_message_iter_open_container(itr, DBUS_TYPE_ARRAY,
	                                     sub_signature+1, &sub_itr) != TRUE) {
		dbus_free(sub_signature);
		return false;
	}

	if (dbus_type_is_fixed(basic_type))
		dbus_message_iter_append_fixed_array(&sub_itr, basic_type, &data, nelem);
	else {
		for (int i = 0; i < nelem; i++) {
			value.str = ((char **)data)[i];
			dbus_message_iter_append_basic(&sub_itr, basic_type, &value);
		}

	}
	dbus_message_iter_close_container(itr, &sub_itr);
	dbus_free(sub_signature);

	return true;
}

static bool
tdbus_write_struct(DBusSignatureIter *sitr, DBusMessageIter *itr,
                   va_list ap)
{
	DBusMessageIter sub_itr;
	DBusSignatureIter sub_sitr;

	if (dbus_message_iter_open_container(itr, DBUS_TYPE_STRUCT,
	                                     NULL, &sub_itr) != TRUE)
		return false;
	dbus_signature_iter_recurse(sitr, &sub_sitr);

	tdbus_write_itr(&sub_sitr, &sub_itr, ap);

	dbus_message_iter_close_container(itr, &sub_itr);

	return true;
}

static bool
tdbus_write_basic(DBusSignatureIter *sitr, DBusMessageIter *itr, va_list ap)
{
	DBusBasicValue value;
	int type = dbus_signature_iter_get_current_type(sitr);

	if (type == DBUS_TYPE_INVALID)
		return false;
	switch (type) {
	case DBUS_TYPE_BYTE:
		value.byt = (char)va_arg(ap, int);
		break;
	case DBUS_TYPE_BOOLEAN:
		value.bool_val = va_arg(ap, int);
		break;

	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		value.str = va_arg(ap, char *);
		break;

	case DBUS_TYPE_UNIX_FD:
		value.fd = va_arg(ap, int);
		break;

	case DBUS_TYPE_INT16: //signed int
		value.i16 = (int16_t)va_arg(ap, int);
		break;
	case DBUS_TYPE_INT32:
		value.i32 = (int32_t)va_arg(ap, int);
		break;
	case DBUS_TYPE_INT64:
		value.i64 =  (int64_t)va_arg(ap, long);
		break;

	case DBUS_TYPE_UINT16: //unsigned int
		value.u16 = (uint16_t)va_arg(ap, unsigned int);
		break;
	case DBUS_TYPE_UINT32:
		value.u32 = (uint32_t)va_arg(ap, unsigned int);
		break;
	case DBUS_TYPE_UINT64:
		value.u64 = (uint64_t)va_arg(ap, unsigned long);
		break;

	case DBUS_TYPE_DOUBLE:
		value.dbl = (double)va_arg(ap, double);
		break;

	default: //impossible
		assert(0);
		break;
	}
	dbus_message_iter_append_basic(itr, type, &value);

	return true;
}

bool
tdbus_write_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
                va_list ap)
{
	int t, advance;

	do {
		DBusBasicValue value;
		int arr_size = 0;

		t = dbus_signature_iter_get_current_type(sitr);

		//we support only simple array for now
		if (t == DBUS_TYPE_ARRAY) {
			arr_size = (int)va_arg(ap, int);
			value.str = (void *)va_arg(ap, void *);
			if (!tdbus_write_array(sitr, itr, arr_size,
			                       value.str))
				return false;

		} else if (t == DBUS_TYPE_STRUCT) {
			if (!tdbus_write_struct(sitr, itr, ap))
				return false;
		} else if (dbus_type_is_basic(t)) {
			if (!tdbus_write_basic(sitr, itr, ap))
				return false;
		} else
			return false;

		advance = dbus_signature_iter_next(sitr);

	} while (advance);

	return true;
}

static bool
tdbus_read_array(DBusSignatureIter *sitr, DBusMessageIter *itr, va_list ap)
{
	int count, basic_type, size;
	void *arr_ptr;
	DBusBasicValue **value_ptr, basic_value;
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
	*va_arg(ap, int *) = count;
	value_ptr = va_arg(ap, DBusBasicValue **);
	*value_ptr = malloc(size);

	if (dbus_type_is_fixed(basic_type)) {
	        dbus_message_iter_get_fixed_array(&sub_itr, &arr_ptr, &count);
	        //asign values back
	        memcpy(*value_ptr, arr_ptr, size);
	} else {
		for (int i = 0; i < count; i++) {
			dbus_message_iter_get_basic(&sub_itr, &basic_value);
			(*value_ptr)[i].str = strdup(basic_value.str);
			dbus_message_iter_next(&sub_itr);
		}
        }

	return true;
}

static bool
tdbus_read_struct(DBusSignatureIter *sitr, DBusMessageIter *itr, va_list ap)
{
	DBusMessageIter sub_iter;
	DBusSignatureIter sub_siter;

	dbus_message_iter_recurse(itr, &sub_iter);
	dbus_signature_iter_recurse(sitr, &sub_siter);
	return tdbus_read_itr(&sub_siter, &sub_iter, ap);
}

static bool
tdbus_read_basic(DBusSignatureIter *sitr, DBusMessageIter *itr, va_list ap)
{
	int type = dbus_message_iter_get_arg_type(itr);
	DBusBasicValue value;

	if (type != dbus_signature_iter_get_current_type(sitr))
		return false;

	dbus_message_iter_get_basic(itr, &value);

	switch (type) {
	case DBUS_TYPE_BYTE:
		*(char*)va_arg(ap, char *) = value.byt;
		break;
	case DBUS_TYPE_BOOLEAN:
		*(bool *)va_arg(ap, bool *) = value.bool_val;
		break;
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		*(const char **)va_arg(ap, const char **) = strdup(value.str);
		break;

	case DBUS_TYPE_UNIX_FD:
		*(int *)va_arg(ap, int *) = value.fd;
		break;

	case DBUS_TYPE_INT16: //signed int
		*(int16_t *)va_arg(ap, int16_t *) = value.i16;
		break;
	case DBUS_TYPE_INT32:
		*(int32_t *)va_arg(ap, int32_t *) = value.i32;
		break;
	case DBUS_TYPE_INT64:
		*(int64_t *)va_arg(ap, int64_t *) = value.i64;
		break;

	case DBUS_TYPE_UINT16: //unsigned int
		*(uint16_t *)va_arg(ap, uint16_t *) = value.u16;
		break;
	case DBUS_TYPE_UINT32:
		*(uint32_t *)va_arg(ap, uint32_t *) = value.u32;
		break;
	case DBUS_TYPE_UINT64:
		*(uint64_t *)va_arg(ap, uint64_t *) = value.u64;
		break;

	case DBUS_TYPE_DOUBLE:
		*(double *)va_arg(ap, double *) = value.dbl;
		break;

	default: //impossible
		assert(0);
		break;
	}
	return true;
}

bool tdbus_read_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
                    va_list ap)
{
	int arg_type;
	int advance = 0;

	while ((arg_type = dbus_message_iter_get_arg_type(itr)) !=
	       DBUS_TYPE_INVALID) {

		if (dbus_signature_iter_get_current_type(sitr) != arg_type)
			return false;

		if (arg_type == DBUS_TYPE_ARRAY) {
			if (!tdbus_read_array(sitr, itr, ap))
				return false;
		} else if (arg_type == DBUS_TYPE_STRUCT) {
			if (!tdbus_read_struct(sitr, itr, ap))
				return false;
		} else if (dbus_type_is_basic(arg_type)) {
			if (!tdbus_read_basic(sitr, itr, ap))
				return false;
		} else //not handling dict and variant
			return false;
		//do something?p
		dbus_message_iter_next(itr);
		advance = dbus_signature_iter_next(sitr);
	}
	//actually testing if we are at the end
	if ((arg_type == DBUS_TYPE_INVALID) && (advance == 0))
		return true;
	else
		return false;
}


/**
 * scanf
 */
void
tdbus_readv(const struct tdbus_message *msg, const char *format, va_list ap)
{
	DBusMessageIter iter;
	DBusSignatureIter sig_itr;
	DBusMessage *message = msg->message;

	//now we go through the list of message
	//actually read the message
	if (dbus_signature_validate(format, NULL) != TRUE)
		return;

	dbus_signature_iter_init(&sig_itr, format);
	dbus_message_iter_init(message, &iter);

	tdbus_read_itr(&sig_itr, &iter, ap);
}

/**
 * printf
 */
bool
tdbus_writev(struct tdbus_message *tdbus_msg, const char *format, va_list ap)
{
	DBusMessage *message;
	DBusMessageIter itr;
	DBusSignatureIter sitr;

	if (dbus_signature_validate(format, NULL) != TRUE)
		return false;

	message = tdbus_msg->message;

	if (!message)
		return false;

	dbus_message_iter_init_append(message, &itr);
	dbus_signature_iter_init(&sitr, format);

	if (!tdbus_write_itr(&sitr, &itr, ap)) {
		dbus_message_unref(message);
		return false;
	}
	return true;
}
