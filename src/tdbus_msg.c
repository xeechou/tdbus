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

void
tdbus_msg_done_dict_entry(struct tdbus_arg_dict_entry *entry)
{
	tdbus_msg_done_arg(&entry->key);
	tdbus_msg_done_arg(&entry->val);
}

static inline void
tdbus_msg_done_arr(struct tdbus_message_arg *arg)
{
	char **strings = arg->arg.arr.a;
	struct tdbus_arg_dict_entry *entries = arg->arg.arr.a;
	struct tdbus_message_arg *objs = arg->arg.arr.a;
	enum tdbus_arg_type elem_type = arg->arg.arr.type;

	for (unsigned i = 0; i < arg->arg.arr.n; i++) {
		if (tdbus_type_is_string(elem_type))
			free(strings[i]);
		else if (tdbus_type_is_dict_entry(elem_type))
			tdbus_msg_done_dict_entry(entries+i);
		else if (tdbus_type_is_object(elem_type))
			tdbus_msg_done_arg(objs+i);
	}
	free(arg->arg.arr.a);
}

void
tdbus_msg_done_variant(struct tdbus_message_arg *arg)
{
	struct tdbus_arg_variant *variant = &arg->arg.variant;
	tdbus_msg_done_arg(variant->arg);
	dbus_free(variant->arg);
}

void
tdbus_msg_done_arg(struct tdbus_message_arg *arg)
{
	if (arg->type == TDBUS_ARG_STRUCT)
		tdbus_msg_itr_done(arg->arg.st);
	else if (arg->type == TDBUS_ARG_VARIANT)
		tdbus_msg_done_variant(arg);
	else if (arg->type == TDBUS_ARG_ARRAY)
		tdbus_msg_done_arr(arg);
	//this is impossible
	else if (arg->type == TDBUS_ARG_DICT_ENTRY)
		tdbus_msg_done_dict_entry(arg->arg.entry);
	else if (arg->type == TDBUS_ARG_STRING ||
	         arg->type == TDBUS_ARG_OBJPATH)
		free(arg->arg.str);
}

/* for insurance, value should be allocated by dbus_malloc */
void
_tdbus_message_itr_init(struct _tdbus_message_itr *itr,
                        struct tdbus_message_arg *value)
{
	itr->it.args = value;
	itr->it.curr = 0;
	tdbus_array_init_fixed(&itr->arr, sizeof(*value), value);
}

TDBUS_EXPORT struct tdbus_message_itr *
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

TDBUS_EXPORT void
tdbus_msg_itr_done(struct tdbus_message_itr *itr)
{
	struct _tdbus_message_itr *_itr =
		tdbus_container_of(itr, struct _tdbus_message_itr, it);
	struct tdbus_message_arg *arg;

	tdbus_array_for_each(arg, &_itr->arr)
		tdbus_msg_done_arg(arg);

	tdbus_array_release(&_itr->arr);
	free(_itr);
}

/******************************************************************************
 * tdbus messenger
 *****************************************************************************/
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

	if (dbus_message_get_type(bus_msg->message) !=
	    DBUS_MESSAGE_TYPE_METHOD_CALL)
		return false;

	bus_msg->bus = bus;
	reply_msg = dbus_connection_send_with_reply_and_block(bus->conn,
	                                                      bus_msg->message,
	                                                      -1, NULL);
	if (!reply_msg) {
		goto err_reply;
	}
	dbus_message_unref(bus_msg->message);
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
