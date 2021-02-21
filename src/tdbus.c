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
		.message = &bus_msg,
	};
	struct tdbus_reply reply = {
		.bus = bus,
		.message = &bus_msg,
	};

	tdbus_reader_from_message(message, &signal, NULL, &reply);
	type = dbus_message_get_type(message);

	switch (type) {
	case DBUS_MESSAGE_TYPE_INVALID:
		return DBUS_HANDLER_RESULT_HANDLED;

	case DBUS_MESSAGE_TYPE_SIGNAL:
		return tdbus_handle_signal(bus, &signal);

	case DBUS_MESSAGE_TYPE_METHOD_CALL:
		read_ret = 1; //be handled by object path
		break;

	case DBUS_MESSAGE_TYPE_ERROR:
	case DBUS_MESSAGE_TYPE_METHOD_RETURN:
		read_ret = 1;
		break;
	}

	return (read_ret == 0) ? DBUS_HANDLER_RESULT_HANDLED :
		DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}


/*******************************************************************************
 * exposed API
 ******************************************************************************/
TDBUS_EXPORT struct tdbus *
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
	bus->n_objs = 0;
	bus->logger = NULL;
	tdbus_array_init(&bus->matched_signals);
	tdbus_array_init(&bus->added_methods);

	dbus_connection_add_filter(bus->conn, tdbus_handle_messages,
	                           bus, //userdata
	                           NULL); //freedata

	return bus;

err_tdbus_alloc:
	dbus_connection_close(conn);
	dbus_connection_unref(conn);
err_bus_alloc:
	return NULL;
}

TDBUS_EXPORT void
tdbus_delete(struct tdbus *bus)
{
	if (bus->service_name)
		dbus_bus_release_name(bus->conn, bus->service_name, NULL);
	free(bus->service_name);

	tdbus_unmatch_signals(bus);
	tdbus_release_methods(bus);

	dbus_connection_flush(bus->conn);
	dbus_connection_close(bus->conn);
	dbus_connection_unref(bus->conn);
	dbus_free(bus);
}

TDBUS_EXPORT void
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

TDBUS_EXPORT void
tdbus_set_logger(struct tdbus *bus, tdbus_logger_fn logger)
{
	bus->logger = logger;
}
