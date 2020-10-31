/*
 * tdbus_msg_writer.c - tdbus message writer implementation
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

#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <dbus/dbus.h>

#include <tdbus.h>
#include "tdbus_internal.h"
#include "tdbus_msg_internal.h"
#include "tdbus_message_iter.h"

static bool
tdbus_write_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
                     struct tdbus_message_itr *mitr);

static inline struct tdbus_message_arg *
_tdbus_msg_itr_write_next(struct tdbus_message_itr *itr)
{
	struct tdbus_message_arg *arg = &itr->args[itr->curr];
	itr->curr += 1;
	return arg;
}


#define tdbus_msg_itr_write_next(itr, type) \
	(!itr->args) ? va_arg(itr->va, type) \
		: *(type *)(&_tdbus_msg_itr_write_next(itr)->arg)


static void
tdbus_msg_itr_get_write_arr(struct tdbus_message_itr *itr, int *count,
                            DBusBasicValue **value)
{
	struct tdbus_message_arg *arg;

	if (!itr->args) {
		*count = va_arg(itr->va, int);
		*value = va_arg(itr->va, void *);
	} else {
		arg = &itr->args[itr->curr];
		if (arg->type != TDBUS_ARG_ARRAY)
			return;
		*count =  arg->arg.arr.n;
		*value = arg->arg.arr.a;
		itr->curr += 1;
	}
}

static inline bool
tdbus_write_single(DBusMessageIter *itr, struct tdbus_message_arg *arg,
                   const char *signature)
{
	DBusSignatureIter sitr;
	struct _tdbus_message_itr mitr;

	dbus_signature_iter_init(&sitr, signature);
	_tdbus_message_itr_init(&mitr, arg);
	return tdbus_write_itr(&sitr, itr, &mitr.it);
}

static void
tdbus_write_dict_entry(DBusMessageIter *itr, DBusSignatureIter *sitr,
                       struct tdbus_arg_dict_entry *e)

{
	char *signature;
	DBusMessageIter sub_itr;
	DBusSignatureIter sub_sitr;
	int key_type = tdbus_arg_type_to_dbus(e->key.type);

	dbus_signature_iter_recurse(sitr, &sub_sitr);

	dbus_message_iter_open_container(itr, DBUS_TYPE_DICT_ENTRY, NULL,
	                                 &sub_itr);
	//append key
	dbus_message_iter_append_basic(&sub_itr, key_type, &e->key.arg);
	//append value
	dbus_signature_iter_next(&sub_sitr);
	signature = dbus_signature_iter_get_signature(&sub_sitr);
	tdbus_write_single(&sub_itr, &e->val, signature);
	dbus_free(signature);

	dbus_message_iter_close_container(itr, &sub_itr);


}

/******************************************************************************
 * tdbus_writer
 *****************************************************************************/

static bool
tdbus_write_array(DBusSignatureIter *sitr, DBusMessageIter *itr,
                  struct tdbus_message_itr *mitr)
{
	int dbus_type;
	enum tdbus_arg_type type;

	DBusMessageIter sub_itr;
	DBusSignatureIter sub_sitr;
	DBusBasicValue *value_ptr = NULL;
	char *signature;
	int nelem = 0;

	dbus_type = dbus_signature_iter_get_element_type(sitr);
	type = tdbus_arg_type_from_dbus(dbus_type);

	dbus_signature_iter_recurse(sitr, &sub_sitr);
	signature = dbus_signature_iter_get_signature(&sub_sitr);

	//getting the array from user
	if (dbus_message_iter_open_container(itr, DBUS_TYPE_ARRAY,
	                                     signature, &sub_itr) != TRUE) {
		dbus_free(signature);
		return false;
	}

	tdbus_msg_itr_get_write_arr(mitr, &nelem, &value_ptr);
	if (!nelem || !value_ptr)
		return false;

	//start writing the array
	if (tdbus_type_is_fixed(type)) {
		dbus_message_iter_append_fixed_array(&sub_itr, dbus_type,
		                                     &value_ptr, nelem);
	} else {
		char **strings = (char **)value_ptr;
		struct tdbus_arg_dict_entry *e =
			(struct tdbus_arg_dict_entry *)value_ptr;
		struct tdbus_message_arg *objs =
			(struct tdbus_message_arg *)value_ptr;

		for (int i = 0; i < nelem; i++) {
			if (tdbus_type_is_string(type))
				dbus_message_iter_append_basic(&sub_itr,
				                               dbus_type,
				                               strings[i]);
			else if (tdbus_type_is_dict_entry(type))
				tdbus_write_dict_entry(&sub_itr, &sub_sitr,
				                       e+i);
			else if (tdbus_type_is_object(type))
				tdbus_write_single(&sub_itr, objs+i,
				                   signature);
		}
	}

	dbus_message_iter_close_container(itr, &sub_itr);
	dbus_free(signature);

	return true;
}

static bool
tdbus_write_struct(DBusSignatureIter *sitr, DBusMessageIter *itr,
                  struct tdbus_message_itr *mitr)
{
	DBusMessageIter sub_itr;
	DBusSignatureIter sub_sitr;
	struct tdbus_message_itr sub_mitr = {0}, *_sub_mitr;
	struct tdbus_message_arg *arg;

	if (dbus_message_iter_open_container(itr, DBUS_TYPE_STRUCT,
	                                     NULL, &sub_itr) != TRUE)
		return false;
	dbus_signature_iter_recurse(sitr, &sub_sitr);

	if (!mitr->args) {
		va_copy(sub_mitr.va, mitr->va);
		_sub_mitr = &sub_mitr;
	} else {
		arg = _tdbus_msg_itr_write_next(mitr);
		if (arg->type != TDBUS_ARG_STRUCT)
			return false;
		_sub_mitr = arg->arg.st;
	}

	tdbus_write_itr(&sub_sitr, &sub_itr, _sub_mitr);

	if (!mitr->args) {
		//swaping va_arg
		va_end(mitr->va);
		va_copy(mitr->va, sub_mitr.va);
		va_end(sub_mitr.va);
	}

	dbus_message_iter_close_container(itr, &sub_itr);

	return true;
}

static bool
tdbus_write_basic(DBusSignatureIter *sitr, DBusMessageIter *itr,
                  struct tdbus_message_itr *mitr)
{
	DBusBasicValue value;
	int type = dbus_signature_iter_get_current_type(sitr);

	if (type == DBUS_TYPE_INVALID)
		return false;
	switch (type) {
	case DBUS_TYPE_BYTE:
		value.byt = tdbus_msg_itr_write_next(mitr, int);
		break;
	case DBUS_TYPE_BOOLEAN:
		value.bool_val = tdbus_msg_itr_write_next(mitr, int);
		break;

	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
		value.str = tdbus_msg_itr_write_next(mitr, char *);
		break;

	case DBUS_TYPE_UNIX_FD:
		value.fd = tdbus_msg_itr_write_next(mitr, int);
		break;

	case DBUS_TYPE_INT16: //signed int
		value.i16 = tdbus_msg_itr_write_next(mitr, int);
		break;
	case DBUS_TYPE_INT32:
		value.i32 = tdbus_msg_itr_write_next(mitr, int);
		break;
	case DBUS_TYPE_INT64:
		value.i64 = tdbus_msg_itr_write_next(mitr, long);
		break;

	case DBUS_TYPE_UINT16: //unsigned int
		value.u16 = tdbus_msg_itr_write_next(mitr, unsigned int);
		break;
	case DBUS_TYPE_UINT32:
		value.u32 = tdbus_msg_itr_write_next(mitr, unsigned int);
		break;
	case DBUS_TYPE_UINT64:
		value.u64 = tdbus_msg_itr_write_next(mitr, unsigned long);
		break;

	case DBUS_TYPE_DOUBLE:
		value.dbl = tdbus_msg_itr_write_next(mitr, double);
		break;

	default: //impossible
		assert(0);
		break;
	}
	dbus_message_iter_append_basic(itr, type, &value);

	return true;
}

static bool
tdbus_write_variant(DBusSignatureIter *sitr, DBusMessageIter *itr,
                    struct tdbus_message_itr *mitr)
{
	int ret = true;
	DBusMessageIter sub_itr;
	struct tdbus_message_arg arg =
		tdbus_msg_itr_write_next(mitr, struct tdbus_message_arg);
	struct tdbus_arg_variant *var = &arg.arg.variant;

	if (dbus_message_iter_open_container(itr, DBUS_TYPE_VARIANT,
	                                     var->signature, &sub_itr) != TRUE)
		return false;
	ret = tdbus_write_single(&sub_itr, var->arg, var->signature);

	dbus_message_iter_close_container(itr, &sub_itr);
	return ret;
}

static bool
tdbus_write_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
                struct tdbus_message_itr *mitr)
{
	int t, advance;

	do {
		t = dbus_signature_iter_get_current_type(sitr);

		//we support only simple array for now
		if (t == DBUS_TYPE_ARRAY) {
			if (!tdbus_write_array(sitr, itr, mitr))
				return false;

		} else if (t == DBUS_TYPE_STRUCT) {
			if (!tdbus_write_struct(sitr, itr, mitr))
				return false;
		} else if (dbus_type_is_basic(t)) {
			if (!tdbus_write_basic(sitr, itr, mitr))
				return false;
		} else if (t == DBUS_TYPE_VARIANT) {
			if (!tdbus_write_variant(sitr, itr, mitr))
				return false;
		} else
			return false;

		advance = dbus_signature_iter_next(sitr);

	} while (advance);

	return true;
}

TDBUS_EXPORT bool
tdbus_writev(struct tdbus_message *tdbus_msg, const char *format, va_list ap)
{
	bool ret;
	struct tdbus_message_itr mitr = {0};

	va_copy(mitr.va, ap);
	ret = tdbus_write_with_itr(tdbus_msg, format, &mitr);
	va_end(mitr.va);

	return ret;
}

TDBUS_EXPORT bool
tdbus_write_with_itr(struct tdbus_message *msg, const char *format,
                     struct tdbus_message_itr *mitr)
{
	DBusMessage *message;
	DBusMessageIter itr;
	DBusSignatureIter sitr;

	if (dbus_signature_validate(format, NULL) != TRUE)
		return false;

	message = msg->message;

	if (!message)
		return false;

	dbus_message_iter_init_append(message, &itr);
	dbus_signature_iter_init(&sitr, format);
	//if you pass mitr here, you need to be sure to have enough memory
	//allocated already, and the
	mitr->curr = 0;

	if (!tdbus_write_itr(&sitr, &itr, mitr)) {
		dbus_message_unref(message);
		return false;
	}
	return true;

}
