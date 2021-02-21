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
	tdbus_read_call_f reader;
};


/*******************************************************************************
 * string writer for introspect
 ******************************************************************************/

struct tdbus_str {
	size_t wn, wa;
	char *written;
};

static bool
tdbus_str_init(struct tdbus_str *writer)
{
	writer->wn = 0;
	writer->wa = 1000;
	writer->written = malloc(writer->wa * sizeof(char));
	if (!writer->written)
		return false;
	return true;
}

static void
tdbus_str_fini(struct tdbus_str *writer)
{
	if (writer->written)
		free(writer->written);
}

static bool
tdbus_str_write(struct tdbus_str *writer, const char *format,
                size_t n2write, ...)
{
	va_list ap;
	char *new_alloc = NULL;
	//realloc
	if (writer->wn + n2write >= writer->wa) {
		new_alloc = realloc(writer->written, writer->wa + 1000);
		if (!new_alloc)
			return false;
		writer->written = new_alloc;
		writer->wa += 1000;
	}
	//write
	va_start(ap, n2write);
	writer->wn += vsprintf(writer->written + writer->wn, format, ap);
	va_end(ap);
	return true;
}

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

static bool
tdbus_server_instropect_method(struct tdbus_str* writer,
                               struct tdbus_method_record *record)
{
	DBusSignatureIter sitr;
	dbus_bool_t advance;
	size_t arg_index;

	const char *format_method_start = "    <method name='%s'>\n";
	const char *format_method_end = "    </method>\n";
	const char *format_arg =
		"      <arg name='arg%d' type='%s' direction='%s' />\n";
	const char *signatures[2] = {record->signature, record->output_signature};
	const char *io[2] = {"in", "out"};

	if (!tdbus_str_write(writer, format_method_start,
	                     strlen(format_method_start)+strlen(record->method),
	                     record->method))
		return false;
	// process args
	arg_index = 0;
	for (int i = 0; i < 2; i++) {
		dbus_signature_iter_init(&sitr, signatures[i]);
		do {
			char *sig = dbus_signature_iter_get_signature(&sitr);
			if (!tdbus_str_write(writer, format_arg,
			                     strlen(format_arg) +
			                     strlen(io[i]) + strlen(sig),
			                     arg_index, sig, io[i]))
				return false;

			dbus_free(sig);
			advance = dbus_signature_iter_next(&sitr);
			arg_index++;
		} while (advance == TRUE);
	}
	if (!tdbus_str_write(writer, "%s", strlen(format_method_end),
		    format_method_end))
		return false;
	return true;
}

static DBusHandlerResult
tdbus_server_reply_introspect(struct tdbus *bus, DBusMessage *reply,
                              struct tdbus_method_record *records,
                              size_t n_records)
{
	static const char *introspect_start =
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
	static const char *introspect_end = "</node>\n";
	static const char *interface_start = "  <interface name='%s'>\n";
	static const char *interface_end = "  </interface>\n";

	struct tdbus_str writer;
	unsigned madv;

	if (!tdbus_str_init(&writer))
		goto fail;

	if (!tdbus_str_write(&writer, "%s", strlen(introspect_start),
	                     introspect_start))
		goto fail;

	//for every interface
	for (unsigned i = 0; i < n_records; i += madv) {
		const char *iface = records[i].interface;
		madv = 0;
		if (!tdbus_str_write(&writer, interface_start,
		                     strlen(interface_start) + strlen(iface),
		                     iface))
			goto fail;
		//for every method
		while (i+madv < n_records &&
		       !strcmp(iface, records[i+madv].interface)) {
			struct tdbus_method_record *record =
				&records[i+madv];

			if (!tdbus_server_instropect_method(&writer, record))
				goto fail;
			madv++;
		}
		//realloc
		if (!tdbus_str_write(&writer, "%s", strlen(interface_end),
		                     interface_end))
			goto fail;
	}

	//write the foot
	if (!tdbus_str_write(&writer, "%s", strlen(introspect_end),
	                     introspect_end))
		goto fail;

	dbus_message_append_args(reply,
	                         DBUS_TYPE_STRING,
	                         &writer.written,
	                         DBUS_TYPE_INVALID);

	tdbus_str_fini(&writer);

	return DBUS_HANDLER_RESULT_HANDLED;
fail:
	tdbus_str_fini(&writer);
	return DBUS_HANDLER_RESULT_NEED_MEMORY;
}

static tdbus_read_call_f
tdbus_server_find_reader(struct tdbus_method_record *records, int n_methods,
                         const struct tdbus_method_call *call)
{
	struct tdbus_method_record *rec = records;
	for (rec = records; rec != records + n_methods; rec++) {
		if (!strcmp(call->method_name, rec->method) &&
		    !strcmp(call->interface, rec->interface))
			return rec->reader;
	}
	return NULL;
}

static DBusHandlerResult
tdbus_server_handle_method(DBusConnection *conn, DBusMessage *message,
                           void *data)
{
	struct tdbus *bus = data;
	DBusHandlerResult result = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	DBusMessage *reply = NULL;
	DBusError err;
	const char *obj_path;
	struct tdbus_method_record *records = bus->added_methods.data;
	tdbus_read_call_f reader;
	int n_records = 0;

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
	tdbus_reader_from_message(message, NULL, &call, NULL);
	obj_path = dbus_message_get_path(message);
	//find the records
	for (int i = 0; i < bus->n_objs; i++) {
		if (!strcmp(obj_path, bus->registered_objs[i].objpath)) {
			size_t start = bus->registered_objs[i].start;
			n_records = bus->registered_objs[i].n_methods;
			records += start;
			break;
		}
	}
	if (!records) //obj not found
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (dbus_message_is_method_call(message,
	                                DBUS_INTERFACE_INTROSPECTABLE,
	                                "Introspect")) {
		//return this xml back to dbus connection
		if (!(reply = dbus_message_new_method_return(message)))
			goto err_new_reply;
		result = tdbus_server_reply_introspect(bus, reply,
		                                       records, n_records);

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
	} else if ((reader = tdbus_server_find_reader(records, n_records,
	                                              &call)) != NULL) {
		reader(&call);
		result = DBUS_HANDLER_RESULT_HANDLED;
	} else
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (reply) {
		result = DBUS_HANDLER_RESULT_HANDLED;
		dbus_connection_send(conn, reply, NULL);
		dbus_message_unref(reply);
	}
	return result;

err_get_property:
	tdbus_handle_error(bus, TDBUS_LOG_WARN, __FUNCTION__, &err);
	dbus_error_free(&err);

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
 * exposed API
 ******************************************************************************/

/**
 * allocating methods
 */
TDBUS_EXPORT bool
tdbus_server_add_methods(struct tdbus *bus, const char *obj_path,
                         unsigned int n_methods,
                         struct tdbus_call_answer *answers)
{
	DBusError err;
	struct tdbus_method_record *records, *method;
	unsigned i;

	if (!n_methods)
		return false;

	if (bus->n_objs > 7 || strlen(obj_path) > 31)
		return false;

	for (int i = 0; i < bus->n_objs; i++) {
		if (!strcmp(bus->registered_objs[i].objpath, obj_path))
			//obj already registered
			return false;
	}

	for (unsigned i = 0; i < n_methods; i++) {
		if (!answers->reader ||
		    strlen(answers->interface) > 31 ||
		    strlen(answers->in_signature) > 31 ||
		    strlen(answers->out_signature) > 15 ||
		    strlen(answers->method) > 15)
			return false;
	}

	records = tdbus_array_add(&bus->added_methods,
	                          n_methods * sizeof(*records));
	if (!records)
		return false;

	for (i = 0, method = records; method != records + n_methods;
	     method++, i++) {
		strcpy(method->interface, answers[i].interface);
		strcpy(method->method, answers[i].method);
		strcpy(method->signature, answers[i].in_signature);
		strcpy(method->output_signature, answers[i].out_signature);
		method->reader = answers[i].reader;
	}

	// add callback
	dbus_error_init(&err);
	if ((dbus_connection_try_register_object_path(bus->conn,
	                                              obj_path, &server_vtable,
	                                              bus, &err)) != TRUE)
		tdbus_handle_error(bus, TDBUS_LOG_WARN, __FUNCTION__, &err);
	dbus_error_free(&err);

	//add new object path
	strcpy(bus->registered_objs[bus->n_objs].objpath, obj_path);
	bus->registered_objs[bus->n_objs].n_methods = n_methods;
	bus->registered_objs[bus->n_objs].start = (bus->n_objs) == 0 ?
		0 : bus->registered_objs[bus->n_objs-1].start +
		bus->registered_objs[bus->n_objs-1].n_methods;
	bus->n_objs += 1;

	return true;
}

TDBUS_EXPORT struct tdbus *
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


void
tdbus_release_methods(struct tdbus *bus)
{
	tdbus_array_release(&bus->added_methods);
	bus->n_objs = 0;
}
