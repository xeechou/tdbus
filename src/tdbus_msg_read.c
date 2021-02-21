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
#include <tdbus.h>

#include "tdbus_internal.h"
#include "tdbus_msg_internal.h"

static bool
tdbus_read_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
               struct tdbus_message_itr *mitr);

//I should return tdbus_arg_value actually
static union tdbus_arg_value *
_tdbus_msg_itr_next(struct tdbus_message_itr *itr, int dbus_type)
{
	struct _tdbus_message_itr *_itr =
		tdbus_container_of(itr, struct _tdbus_message_itr, it);
	struct tdbus_message_arg *arg;

	arg = tdbus_array_add(&_itr->arr, sizeof(struct tdbus_message_arg));
	arg->type = tdbus_arg_type_from_dbus(dbus_type);
	itr->args = _itr->arr.data;

	itr->curr += 1;
	return &arg->arg;
}

#define tdbus_msg_itr_next(itr, type, dbus_type)                        \
	(!itr->args) ? va_arg(itr->va, type) \
	: (type)_tdbus_msg_itr_next(itr, dbus_type)

static DBusBasicValue *
tdbus_msg_itr_get_arr(struct tdbus_message_itr *itr, enum tdbus_arg_type type,
                      int count)
{
	void **value_ptr, *value;
	union tdbus_arg_value *curr;

	value = count ? malloc(count * tdbus_get_msg_arg_size(type)) : NULL;
	if (count && !value)
		return NULL;

	if (!itr->args) {
		*va_arg(itr->va, int *) = count;
		value_ptr = va_arg(itr->va,  void**);
		*value_ptr = value;
	} else {
		curr = _tdbus_msg_itr_next(itr, type);
		curr->arr.n = count;
		curr->arr.type = type;
		curr->arr.a = value;
	}
	return value;
}

static void
tdbus_get_basic(union tdbus_arg_value *dst, int type,
                const DBusBasicValue *src)
{
	switch (type) {
	case DBUS_TYPE_BYTE:
		dst->c = src->byt;
		break;
	case DBUS_TYPE_BOOLEAN:
		dst->b = src->bool_val;
		break;
	case DBUS_TYPE_STRING:
	case DBUS_TYPE_OBJECT_PATH:
	case DBUS_TYPE_SIGNATURE:
		dst->str = strdup(src->str);
		break;
	case DBUS_TYPE_UNIX_FD:
		dst->fd = src->fd;
		break;

	case DBUS_TYPE_INT16: //signed int
		dst->i16 = src->i16;
		break;
	case DBUS_TYPE_INT32:
		dst->i32 = src->i32;
		break;
	case DBUS_TYPE_INT64:
		dst->i64 = src->i64;
		break;

	case DBUS_TYPE_UINT16: //unsigned int
		dst->u16 = src->u16;
		break;
	case DBUS_TYPE_UINT32:
		dst->u32 = src->u32;
		break;
	case DBUS_TYPE_UINT64:
		dst->u64 = src->u64;
		break;

	case DBUS_TYPE_DOUBLE:
		dst->d = src->dbl;
		break;

	default: //impossible
		assert(0);
		break;
	}
}

/* read itr and the sig_itr to this arg, the signature should be generated
 * from itr. */
static inline bool
tdbus_get_single(DBusMessageIter *itr, struct tdbus_message_arg *arg)
{
	int ret = true;
	int type = dbus_message_iter_get_arg_type(itr);
	struct _tdbus_message_itr mitr = {0};
	DBusSignatureIter sitr;
	char *signature = NULL;

        signature = dbus_message_iter_get_signature(itr);
	dbus_signature_iter_init(&sitr, signature);

        arg->type = type;
        _tdbus_message_itr_init(&mitr, arg);
	ret = tdbus_read_itr(&sitr, itr, &mitr.it);
	dbus_free(signature);
	return ret;
}

static void
tdbus_get_dict_entry(DBusMessageIter *itr, struct tdbus_arg_dict_entry *entry)
{
	int key_type;
	DBusBasicValue basic_value;
	DBusMessageIter sub_itr;

	dbus_message_iter_recurse(itr, &sub_itr);
	//get key
	key_type = dbus_message_iter_get_arg_type(&sub_itr);
	dbus_message_iter_get_basic(&sub_itr, &basic_value);
	entry->key.type = tdbus_arg_type_from_dbus(key_type);
	tdbus_get_basic(&entry->key.arg, key_type, &basic_value);
	dbus_message_iter_next(&sub_itr);

	//get value, as for value, you would not know what it is
	tdbus_get_single(&sub_itr, &entry->val);
	dbus_message_iter_next(&sub_itr);
}

/******************************************************************************
 * tdbus_reader
 *****************************************************************************/

static bool
tdbus_read_array(DBusSignatureIter *sitr, DBusMessageIter *itr,
                 struct tdbus_message_itr *mitr)
{
	int count, dbus_type, size;
	void *arr_ptr, *value;
	DBusBasicValue basic_value;
	DBusMessageIter sub_itr;
	DBusSignatureIter sub_sitr;
	enum tdbus_arg_type type;

	dbus_message_iter_recurse(itr, &sub_itr);
	dbus_signature_iter_recurse(sitr, &sub_sitr);
	dbus_type = dbus_message_iter_get_element_type(itr);
	type = tdbus_arg_type_from_dbus(dbus_type);

	if (dbus_signature_iter_get_element_type(sitr) != dbus_type)
		return false;

	count = dbus_message_iter_get_element_count(itr);
	size = count * tdbus_get_msg_arg_size(type);

        value = tdbus_msg_itr_get_arr(mitr, type, count);
        if (count && !value)
	        return false;

        ////step 2 copying values
        if (count == 0) {
	        //if we are in a empty array, do nothing
        } else if (tdbus_type_is_fixed(type)) {
		//as in document, the iter should be "in" the array as subiter
	        dbus_message_iter_get_fixed_array(&sub_itr, &arr_ptr, &count);
	        memcpy(value, arr_ptr, size);
	} else if (tdbus_type_is_string(type)) {
		char **strings = value;
		for (int i = 0; i < count; i++) {
			dbus_message_iter_get_basic(&sub_itr, &basic_value);
			strings[i] = strdup(basic_value.str);
			dbus_message_iter_next(&sub_itr);
		}
	} else if (tdbus_type_is_dict_entry(type)) {
		struct tdbus_arg_dict_entry *e = value;
		for (struct tdbus_arg_dict_entry *i = e; i < e + count; i++ ) {
			tdbus_get_dict_entry(&sub_itr, i);
			dbus_message_iter_next(&sub_itr);
		}
	} else if (tdbus_type_is_object(type)) {
		struct tdbus_message_arg *objs = value;
		for (struct tdbus_message_arg *i = objs; i < objs+count; i++) {
			tdbus_get_single(&sub_itr, i);
			dbus_message_iter_next(&sub_itr);
		}
	} else
		return false;

	return true;
}

static bool
tdbus_read_struct(DBusSignatureIter *sitr, DBusMessageIter *itr,
                  struct tdbus_message_itr *mitr)
{
	int ret;
	DBusMessageIter sub_iter;
	DBusSignatureIter sub_siter;
	struct tdbus_message_itr sub_mitr = {0}, *_sub_mitr;
	union tdbus_arg_value *arg;

	//we need to start a new sub_miter here, if using va, copy the va_list
	//to generate a new miter.
	if (!mitr->args) {
		va_copy(sub_mitr.va, mitr->va);
		_sub_mitr = &sub_mitr;
	} else {
		arg = _tdbus_msg_itr_next(mitr, DBUS_TYPE_STRUCT);
		arg->st = tdbus_msg_itr_new();
		if (!arg->st)
			return false;
		_sub_mitr = arg->st;
	}

	dbus_message_iter_recurse(itr, &sub_iter);
	dbus_signature_iter_recurse(sitr, &sub_siter);
	ret = tdbus_read_itr(&sub_siter, &sub_iter, _sub_mitr);
	//then copy back the va_list back to mitr->va
	if (!mitr->args) {
		va_end(mitr->va);
		va_copy(mitr->va, sub_mitr.va);
		va_end(sub_mitr.va);
	}

	return ret;
}

static bool
tdbus_read_basic(DBusSignatureIter *sitr, DBusMessageIter *itr,
                 struct tdbus_message_itr *mitr)
{
	int type = dbus_message_iter_get_arg_type(itr);
	DBusBasicValue value;
	union tdbus_arg_value *tdbus_val;

	if (type != dbus_signature_iter_get_current_type(sitr))
		return false;

	dbus_message_iter_get_basic(itr, &value);
	tdbus_val = tdbus_msg_itr_next(mitr, union tdbus_arg_value *, type);
	tdbus_get_basic(tdbus_val, type, &value);

	return true;
}

static bool
tdbus_read_variant(DBusMessageIter *itr, struct tdbus_message_itr *mitr)
{
	bool ret = true;
	char *signature = NULL;
	DBusSignatureIter sub_sitr = {0};
	DBusMessageIter sub_itr = {0};
	struct _tdbus_message_itr sub_mitr = {0};
	DBusError err;
	struct tdbus_arg_variant *variant = NULL;
	struct tdbus_message_arg *arg = NULL;

	dbus_message_iter_recurse(itr, &sub_itr);
	signature = dbus_message_iter_get_signature(&sub_itr);
	dbus_error_init(&err);

	//verify the signature of this variant.
	if (!signature || strlen(signature) >= 16 ||
	    !dbus_signature_validate_single(signature, &err)) {
		ret = false;
		goto out;
	}

	dbus_signature_iter_init(&sub_sitr, signature);

        //initialize the variant subiter,
	arg = (tdbus_msg_itr_next(mitr, struct tdbus_message_arg *,
	                              DBUS_TYPE_VARIANT));
	variant = &arg->arg.variant;
	strcpy(variant->signature, signature);
	variant->arg = dbus_malloc(sizeof(*arg));
	_tdbus_message_itr_init(&sub_mitr, variant->arg);

	//now we can finally read to this iterator
	ret = tdbus_read_itr(&sub_sitr, &sub_itr, &sub_mitr.it);

out:
	dbus_error_free(&err);
	dbus_free(signature);
	return ret;
}

static bool
tdbus_read_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
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
		} else if (arg_type == DBUS_TYPE_VARIANT) {
			if (!tdbus_read_variant(itr, mitr))
				return false;
		} else
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

TDBUS_EXPORT bool
tdbus_readv(const struct tdbus_message *msg, const char *format, va_list ap)
{
	struct tdbus_message_itr itr = {0};
	bool ret;

	va_copy(itr.va, ap);
	ret = tdbus_read_with_iter(msg, format, &itr);
	va_end(itr.va);

	return ret;
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
