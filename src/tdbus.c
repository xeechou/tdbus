/*
 * tdbus.c - dbus connection implementation
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
#include <dbus/dbus-shared.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <dbus/dbus.h>

#include <tdbus.h>
#include "tdbus_internal.h"


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

/**
 * @brief handle client messages.
 *
 * Handles signal and reply, since it runs before the object path handlers does.
 */
static DBusHandlerResult
tdbus_handle_messages(DBusConnection *conn, DBusMessage *message, void *data)
{
	//handle incomeing messages,
	struct tdbus *bus = data;
	int type, read_ret = 0;

	struct tdbus_message bus_msg = {
		.message = message,
		.bus = bus,
	};
	struct tdbus_signal signal = {
		.bus = bus,
		.user_data = bus->signal_userdata,
		.message = &bus_msg,
	};
	struct tdbus_reply reply = {
		.bus = bus,
		.user_data = bus->reply_userdata,
		.message = &bus_msg,
	};

	tdbus_reader_from_message(message, &signal, NULL, &reply);
	type = dbus_message_get_type(message);

	switch (type) {
	case DBUS_MESSAGE_TYPE_INVALID:
		return DBUS_HANDLER_RESULT_HANDLED;

	case DBUS_MESSAGE_TYPE_SIGNAL:
		read_ret = (bus->read_signal_cb) ?
			bus->read_signal_cb(&signal) : 0;
		break;

	case DBUS_MESSAGE_TYPE_METHOD_CALL:
		read_ret = 1; //be handled by object path
		break;

	case DBUS_MESSAGE_TYPE_ERROR:
	case DBUS_MESSAGE_TYPE_METHOD_RETURN:
		read_ret = (bus->read_reply_cb) ?
			bus->read_reply_cb(&reply) : 0;
		break;
	}

	return (read_ret == 0) ? DBUS_HANDLER_RESULT_HANDLED :
		DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}


/*******************************************************************************
 * exposed API
 ******************************************************************************/
struct tdbus *
tdbus_new(enum TDBUS_TYPE type)
{
	DBusConnection *conn = NULL;
	DBusBusType bustype = type == SYSTEM_BUS ?
		DBUS_BUS_SYSTEM : DBUS_BUS_SESSION;
	struct tdbus *bus;

	dbus_connection_set_change_sigpipe(FALSE);

	//either this or dbus_get_private
	conn = dbus_bus_get_private(bustype, NULL);
	if (!conn)
		goto err_bus_alloc;

	dbus_connection_set_exit_on_disconnect(conn, FALSE);

	bus = dbus_malloc0(sizeof(struct tdbus));
	if (!bus)
		goto err_tdbus_alloc;

	bus->conn = conn;
	bus->non_block = false;
	if (!tdbus_init_timeouts(bus))
		goto err_init_timeouts;

	dbus_connection_add_filter(bus->conn, tdbus_handle_messages,
	                           bus, //userdata
	                           NULL); //freedata

	return bus;

err_init_timeouts:
	dbus_free(bus);
err_tdbus_alloc:
	dbus_connection_close(conn);
	dbus_connection_unref(conn);
err_bus_alloc:
	return NULL;
}

void
tdbus_delete(struct tdbus *bus)
{
	if (bus->service_name)
		dbus_bus_release_name(bus->conn, bus->service_name, NULL);
	free(bus->service_name);

	dbus_connection_flush(bus->conn);
	tdbus_release_timeouts(bus);
	dbus_connection_close(bus->conn);
	dbus_connection_unref(bus->conn);
	dbus_free(bus);
}

void
tdbus_dispatch_once(struct tdbus *bus)
{
	int r;

	if (!bus->non_block)
		dbus_connection_read_write_dispatch(bus->conn, -1);
	else {
		do
			r = dbus_connection_dispatch(bus->conn);
		while (r == DBUS_DISPATCH_DATA_REMAINS);

		if (r != DBUS_DISPATCH_COMPLETE) {
			//oops!, some error happened
		}
	}
}

void
tdbus_set_reader(struct tdbus *bus,
                 tdbus_read_signal_f sig_reader, void *ud_sig,
                 tdbus_read_call_f method_reply, void *ud_mc,
                 tdbus_read_reply_f reply_reader, void *ud_rp)
{
	bus->signal_userdata = ud_sig;
	bus->read_signal_cb = sig_reader;

	bus->read_method_cb = method_reply;
	bus->method_userdata = ud_mc;

	bus->read_reply_cb = reply_reader;
	bus->reply_userdata = ud_rp;
}

struct tdbus_message *
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

struct tdbus_message *
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

void
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
		//free the message right here
		dbus_connection_send(bus->conn, bus_msg->message, NULL);
		tdbus_free_message(bus_msg);
	}
}

void
tdbus_free_message(struct tdbus_message *bus_msg)
{
	dbus_message_unref(bus_msg->message);
	dbus_free(bus_msg);
}
