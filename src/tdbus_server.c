/*
 * tdbu_server.c - tdbus server implementation
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

#include <stdio.h>
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

struct tdbus_method_record {
	char method[16];
	char output_signature[16];
	char interface[32];
	char signature[32];
};

static DBusHandlerResult
tdbus_server_get_property(struct tdbus *bus, DBusMessage *reply,
                          const char *property)
{
	DBusConnection *conn = bus->conn;
	const char *version = "0.1";

	if (!strcmp(property, "version"))
		dbus_message_append_args(reply,
		                         DBUS_TYPE_STRING, &version,
		                         DBUS_TYPE_INVALID);
	else
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	if (!dbus_connection_send(conn, reply, NULL))
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	return DBUS_HANDLER_RESULT_HANDLED;
}

static char *
tdbus_server_instropect_method(struct tdbus_method_record *record)
{
	char *output = NULL;
	char *cursor;
	DBusSignatureIter sitr;
	dbus_bool_t advance;
	size_t arg_index, wa;

	const char *format_method_start = "    <method name='%s'>\n";
	const char *format_method_end = "    </method>\n";
	const char *format_arg =
		"      <arg name='arg%d' type='%s' direction='%s' />\n";
	const char *signatures[2] = {record->signature, record->output_signature};
	const char *io[2] = {"in", "out"};

	output = malloc(1000);
	if (!output)
		return NULL;
	wa = 1000;

	cursor = output;
	cursor += sprintf(cursor, format_method_start, record->method);
	// process args
	arg_index = 0;
	for (int i = 0; i < 2; i++) {
		dbus_signature_iter_init(&sitr, signatures[i]);
		do {
			char *curr_sig = dbus_signature_iter_get_signature(&sitr);
			if (wa < cursor - output + (strlen(format_arg) +
			                            strlen(curr_sig) + 4)) {
				char *new_alloc = realloc(output, wa + 1000);
				if (!new_alloc) {
					free(output);
					return NULL;
				}
			}

			cursor += sprintf(cursor, format_arg, arg_index,
			                  curr_sig, io[i]);
			dbus_free(curr_sig);
			advance = dbus_signature_iter_next(&sitr);
			arg_index++;
		} while (advance == TRUE);
	}

	cursor += sprintf(cursor, "%s", format_method_end);

	return output;
}

static DBusHandlerResult
tdbus_server_reply_introspect(struct tdbus *bus, DBusMessage *reply)
{
	static const char *introspect_template0 =
		DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
		"<node>\n"
		"  <interface name='org.freedesktop.DBus.Introspectable'>\n"
		"    <method name='Introspect'>\n"
		"      <arg name='data' type='s' direction='out' />\n"
		"    </method>\n"
		"  </interface>\n"

		"  <interface name='org.freedesktop.DBus.Properties'>\n"
		"    <method name='Get'>\n"
		"      <arg name='interface' type='s' direction='in' />\n"
		"      <arg name='property'  type='s' direction='in' />\n"
		"      <arg name='value'     type='s' direction='out' />\n"
		"    </method>\n"
		"  </interface>\n";
	static const char *introspect_template1 = "</node>\n";

	static const char *interface_start = "  <interface name='%s'>\n";
	static const char *interface_end = "  </interface>\n";

	char *written = NULL;
	size_t wa = 1000;
	int madv = 0, wn = 0;
	//dealing with every interface, this must be horrible
	written = malloc(wa * sizeof(char));
	if (!written)
		goto err_alloc;
	wn += sprintf(written+wn, "%s", introspect_template0);

	//for every interface
	for (int i = 0; i < bus->n_methods; i+= madv) {
		const char *iface = bus->method_records[i].interface;
		//realloc
		if (wa - wn <= strlen(interface_start) + strlen(iface)) {
			char *new_alloc = realloc(written, (wa+1000));
			if (!new_alloc)
				goto err_alloc;
			written = new_alloc;
		}
		wn += sprintf(written+wn, interface_start, iface);
		//for every method
		while (!strcmp(iface, bus->method_records[i+madv].interface)) {
			struct tdbus_method_record *record =
				&bus->method_records[i+madv];
			//this is horrible
			char *method = tdbus_server_instropect_method(record);
			// realloc
			if (wa - wn <= strlen(method)) {
				char *new_alloc = realloc(written, (wa+1000));
				if (!new_alloc)
					goto err_alloc;
				written = new_alloc;
			}
			wn += sprintf(written+wn, "%s", method);
			free(method);
			madv++;
		}
		//realloc
		if (wa - wn <= strlen(interface_end)) {
			char *new_alloc = realloc(written, (wa+1000));
			if (!new_alloc)
				goto err_alloc;
			written = new_alloc;
		}
		wn += sprintf(written+wn, "%s", interface_end);
	}

	//write the foot
        if (wa - wn <= strlen(introspect_template1)) {
	        char *new_alloc = realloc(written, (wa + 1000) * sizeof(char));
	        if (!new_alloc)
		        goto err_alloc;
	        written = new_alloc;
        }
        wn += sprintf(written+wn, "%s", introspect_template1);
	dbus_message_append_args(reply,
	                         DBUS_TYPE_STRING,
	                         &written,
	                         DBUS_TYPE_INVALID);

	free(written);
	return DBUS_HANDLER_RESULT_HANDLED;
err_alloc:
	if (written)
		free(written);
	return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static DBusHandlerResult
tdbus_server_handle_method(DBusConnection *conn, DBusMessage *message,
                           void *data)
{
	struct tdbus *bus = data;
	DBusHandlerResult result;
	DBusMessage *reply = NULL;
	DBusError err;

	struct tdbus_message bus_msg = {
		.bus = bus,
		.message = message,
	};
	struct tdbus_method_call call = {
		.bus = bus,
		.message = &bus_msg,
		.user_data = data,
	};

	dbus_error_init(&err);

	if (dbus_message_is_method_call(message,
	                                DBUS_INTERFACE_INTROSPECTABLE,
	                                "Introspect")) {
		//return this xml back to dbus connection
		if (!(reply = dbus_message_new_method_return(message)))
			goto err_new_reply;
		result = tdbus_server_reply_introspect(bus, reply);

	} else if (dbus_message_is_method_call(message,
	                                       DBUS_INTERFACE_PROPERTIES,
	                                       "Get")) {
		const char *interface, *property;

		if (!dbus_message_get_args(message, &err,
		                           DBUS_TYPE_STRING, &interface,
		                           DBUS_TYPE_STRING, &property,
		                           DBUS_TYPE_INVALID))
			goto err_get_property;
		if (!(reply = dbus_message_new_method_return(message)))
			goto err_new_reply;
		result = tdbus_server_get_property(bus, reply, property);
	} else if (bus->read_method_cb) {
		tdbus_reader_from_message(message, NULL, &call, NULL);
		bus->read_method_cb(&call); //may send message here
	} else
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (reply) {
		result = DBUS_HANDLER_RESULT_HANDLED;
		dbus_connection_send(conn, reply, NULL);
		dbus_message_unref(reply);
	}
	return result;

err_get_property:

err_new_reply:
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	result = DBUS_HANDLER_RESULT_HANDLED;
	dbus_connection_send(conn, reply, NULL);
	dbus_message_unref(reply);
	return result;
}

static void
tdbus_server_unregister(DBusConnection *conn, void *user_data)
{}


static const DBusObjectPathVTable server_vtable = {
	.message_function = tdbus_server_handle_method,
	.unregister_function = tdbus_server_unregister,
};


/*******************************************************************************
 * exposed
 ******************************************************************************/


/**
 * allocating methods
 */
bool
tdbus_server_add_method(struct tdbus *bus, const char *obj_path,
                        const char *interface, const char *signature)
{
	size_t ns;
	struct tdbus_method_record new_record;
	DBusError err;

	if (strlen(interface) > 31 || strlen(signature) > 31)
		return false;

	if (!bus->method_records) {
		bus->method_records =
			dbus_malloc0(sizeof(struct tdbus_method_record) * 4);
		bus->n_methods = 0;
		bus->n_method_alloc = 4;
	}

	if (bus->n_methods >= bus->n_method_alloc) {
		ns = bus->n_method_alloc * 2;
		bus->method_records =
			dbus_realloc(bus->method_records,
			             sizeof(struct tdbus_method_record) * ns);
		bus->n_method_alloc = ns;
	}

	strcpy(new_record.interface, interface);
	strcpy(new_record.signature, signature);
	bus->method_records[bus->n_methods] = new_record;
	bus->n_methods += 1;
	dbus_error_init(&err);
	if ((dbus_connection_try_register_object_path(bus->conn,
	                                              obj_path, &server_vtable,
	                                              bus, &err)) != TRUE) {
		perror("register object path not succeed\n");
	}
	dbus_error_free(&err);
	return true;
}


struct tdbus *
tdbus_new_server(enum TDBUS_TYPE type, const char *bus_name)
{
	struct tdbus *bus = tdbus_new(type);
	if (!bus)
		return NULL;
	if (dbus_bus_request_name(bus->conn, bus_name,
	                          DBUS_NAME_FLAG_REPLACE_EXISTING |
	                          DBUS_NAME_FLAG_ALLOW_REPLACEMENT,
	                          NULL) != TRUE) {
		tdbus_delete(bus);
		return NULL;
	}
	bus->service_name = strdup(bus_name);
	return bus;
}
