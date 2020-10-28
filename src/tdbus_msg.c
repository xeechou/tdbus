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
#include "tdbus_message_iter.h"

/*******************************************************************************
 * tdbus_msg_itr
 ******************************************************************************/

struct _tdbus_message_itr {
	struct tdbus_message_itr it;
	struct tdbus_array arr;
};


static enum tdbus_arg_type
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


#define tdbus_container_of(ptr, type, member)                                  \
  ({                                                                           \
    const __typeof__(((type *)0)->member) *__mptr = (ptr);                     \
    (type *)((char *)__mptr - offsetof(type, member));                         \
  })


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

static inline struct tdbus_message_arg *
_tdbus_msg_itr_write_next(struct tdbus_message_itr *itr)
{
	struct tdbus_message_arg *arg = &itr->args[itr->curr];
	itr->curr += 1;
	return arg;
}

#define tdbus_msg_itr_next(itr, type, dbus_type)                               \
  (!itr->args) ? va_arg(itr->va, type)                                         \
            : (type)_tdbus_msg_itr_next(itr, dbus_type)

#define tdbus_msg_itr_write_next(itr, type) \
	(!itr->args) ? va_arg(itr->va, type) \
		: *(type *)(&_tdbus_msg_itr_write_next(itr)->arg)

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

static void
tdbus_msg_itr_done_arr(struct tdbus_message_arg *arg)
{
	char **strings = arg->arg.arr.a;

	if (arg->arg.arr.type == TDBUS_ARG_STRING)
		for (unsigned i = 0; i < arg->arg.arr.n; i++)
			free(strings[i]);
	free(arg->arg.arr.a);
}

struct tdbus_message_itr *
tdbus_msg_itr_new(void)
{
	struct _tdbus_message_itr *itr = malloc(sizeof(*itr));

	if (!itr)
		return NULL;

	//a invlid address so it wont be  tested postive for itr->va
	itr->it.args = (void *)0xff;
	itr->it.curr = 0;

	tdbus_array_init(&itr->arr);

	return &itr->it;
}

void
tdbus_msg_itr_done(struct tdbus_message_itr *itr)
{
	struct _tdbus_message_itr *_itr =
		tdbus_container_of(itr, struct _tdbus_message_itr, it);
	struct tdbus_message_arg *arg;

	tdbus_array_for_each(arg, &_itr->arr) {
		if (arg->type == TDBUS_ARG_STRUCT)
			tdbus_msg_itr_done(arg->arg.st);
		else if (arg->type == TDBUS_ARG_ARRAY)
			tdbus_msg_itr_done_arr(arg);
		else if (arg->type == TDBUS_ARG_STRING ||
		         arg->type == TDBUS_ARG_OBJPATH)
			free(arg->arg.str);
	}
	tdbus_array_release(&_itr->arr);
	free(_itr);
}

/*******************************************************************************
 * tdbus_reader
 ******************************************************************************/

bool tdbus_write_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
                     struct tdbus_message_itr *mitr);

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
		} else //not handling dict and variant
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

/*******************************************************************************
 * tdbus_writer
 ******************************************************************************/

static bool
tdbus_write_array(DBusSignatureIter *sitr, DBusMessageIter *itr,
                  struct tdbus_message_itr *mitr)
{
	int basic_type;
	DBusMessageIter sub_itr;
	DBusBasicValue value, *value_ptr = NULL;
	char *sub_signature;
	int nelem = 0;

	basic_type = dbus_signature_iter_get_element_type(sitr);

	if (!dbus_type_is_basic(basic_type))
		return false;

	sub_signature = dbus_signature_iter_get_signature(sitr);

	if (dbus_message_iter_open_container(itr, DBUS_TYPE_ARRAY,
	                                     sub_signature+1, &sub_itr) != TRUE) {
		dbus_free(sub_signature);
		return false;
	}

	tdbus_msg_itr_get_write_arr(mitr, &nelem, &value_ptr);
	if (!nelem || !value_ptr)
		return false;

	if (dbus_type_is_fixed(basic_type))
		dbus_message_iter_append_fixed_array(&sub_itr, basic_type,
		                                     &value_ptr, nelem);
	else {
		for (int i = 0; i < nelem; i++) {
			value.str = ((char **)value_ptr)[i];
			dbus_message_iter_append_basic(&sub_itr, basic_type, &value);
		}

	}
	dbus_message_iter_close_container(itr, &sub_itr);
	dbus_free(sub_signature);

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

bool
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


/*******************************************************************************
 * tdbus messenger
 ******************************************************************************/
void
tdbus_reader_from_message(DBusMessage *message, struct tdbus_signal *signal,
                          struct tdbus_method_call *call,
                          struct tdbus_reply *reply)
{
	const char *member, *iface, *obj_path, *signature, *sender,
		*error_name;

	member = dbus_message_get_member(message);
	obj_path = dbus_message_get_path(message);
	signature = dbus_message_get_signature(message);
	iface = dbus_message_get_interface(message);
	sender = dbus_message_get_sender(message);
	error_name = dbus_message_get_error_name(message);

	if (signal) {
		signal->signal_name = member;
		signal->sender = sender;
		signal->interface = iface;
		signal->signature = signature;
	}

	if (call) {
		call->interface = iface;
		call->sender = sender;
		call->method_name = member;
		call->object_path = obj_path;
	}

	if (reply) {
		reply->sender = sender;
		reply->interface = iface;
		reply->method_name = member;
		reply->error_name = error_name;
		reply->signature = signature;
	}
}

static void
tdbus_notify_reply(DBusPendingCall *pending, void *user_data)
{
	//now we need actually a reply message
	struct tdbus_message *bus_msg = user_data;
	DBusMessage *message = dbus_pending_call_steal_reply(pending);
	struct tdbus_reply reply = {
		.bus = bus_msg->bus,
		.user_data = bus_msg->user_data,
		.message = bus_msg,
	};

	tdbus_reader_from_message(message, NULL, NULL, &reply);
	bus_msg->message = message;
	bus_msg->read_reply(&reply);

	dbus_message_unref(message);
}

TDBUS_EXPORT struct tdbus_message *
tdbus_call_method(const char *dest, const char *path,
                  const char *interface, const char *method,
                  tdbus_read_reply_f reply, void *user_data)
{
	DBusMessage *message;
	struct tdbus_message *bus_msg;

	if (!dest || !method || !interface || !path)
		return false;

	message = dbus_message_new_method_call(dest, path, interface, method);
	if (!message)
		return NULL;

	bus_msg = dbus_malloc0(sizeof(struct tdbus_message));
	if (!bus_msg) {
		dbus_message_unref(message);
		return NULL;
	}

	bus_msg->message = message;
	bus_msg->read_reply = reply;
	bus_msg->user_data = user_data;

	return bus_msg;
}

TDBUS_EXPORT struct tdbus_message *
tdbus_reply_method(const struct tdbus_message *reply_to,
                   const char *err_name)
{
	DBusMessage *message;
	struct tdbus_message *bus_msg;

	if (!reply_to->message)
		return NULL;

	if (err_name)
		message = dbus_message_new_error(reply_to->message,
		                                 err_name, NULL);
	else

          message = dbus_message_new_method_return(reply_to->message);

	bus_msg = dbus_malloc0(sizeof(struct tdbus_message));
	if (!bus_msg) {
		dbus_message_unref(message);
		return NULL;
	}
	bus_msg->message = message;

	return bus_msg;
}

TDBUS_EXPORT void
tdbus_send_message(struct tdbus *bus, struct tdbus_message *bus_msg)
{
	DBusPendingCall *pending = NULL;

	bus_msg->bus = bus;
	if (bus_msg->read_reply) {
		dbus_connection_send_with_reply(bus->conn, bus_msg->message,
		                                &pending, -1);
		dbus_pending_call_set_notify(pending, tdbus_notify_reply,
		                             bus_msg, dbus_free);
		dbus_pending_call_unref(pending);
		dbus_message_unref(bus_msg->message);

	} else {
		dbus_message_set_no_reply(bus_msg->message, TRUE);
		//free the message right here
		dbus_connection_send(bus->conn, bus_msg->message, NULL);
		tdbus_free_message(bus_msg);
	}
}

TDBUS_EXPORT bool
tdbus_send_message_block(struct tdbus *bus, struct tdbus_message *bus_msg,
                         struct tdbus_reply *reply)
{
	DBusMessage *reply_msg;
	DBusError err;

	if (dbus_message_get_type(bus_msg->message) !=
	    DBUS_MESSAGE_TYPE_METHOD_RETURN)
		return false;

	bus_msg->bus = bus;
	reply_msg = dbus_connection_send_with_reply_and_block(bus->conn,
	                                                      bus_msg->message,
	                                                      -1, &err);
	dbus_message_unref(bus_msg->message);

	if (!reply_msg) {
		dbus_error_free(&err);
		goto err_reply;
	}
	bus_msg->message = reply_msg;

	if (reply) {
		reply->bus = bus;
		tdbus_reader_from_message(reply_msg, NULL, NULL, reply);
		reply->message = bus_msg;
	} else {
		tdbus_free_message(bus_msg);
	}
	return true;
err_reply:
	tdbus_free_message(bus_msg);
	return false;
}

TDBUS_EXPORT void
tdbus_free_message(struct tdbus_message *bus_msg)
{
	dbus_message_unref(bus_msg->message);
	dbus_free(bus_msg);
}
