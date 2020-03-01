/*
 * dbus.c - dbus connection implementation
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
#include <errno.h>
#include <sys/timerfd.h>
#include <dbus/dbus.h>

#include "tdbus.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tdbus_timeout_record {
	int timerfd;
	DBusTimeout *timeout;
};

/*
 * the only use of bus message right now is the reply
 */
struct tdbus_message {
	struct tdbus *bus;
	DBusMessage *message;
	tdbus_read_reply_f read_reply;
	void *user_data;
};

struct tdbus {
	//I dont know that is inside
	struct DBusConnection *conn;
	bool non_block;
	bool is_server;

	/* watchers */
	tdbus_add_watch_f add_watch_cb;
	tdbus_rm_watch_f rm_watch_cb;
	tdbus_ch_watch_f ch_watch_cb;
	void *watch_userdata;
	/* timeouts */
	struct tdbus_timeout_record *timeouts;
	size_t timeouts_used,  timeouts_allocated;

	/* readers */
	tdbus_read_signal_f read_signal_cb;
	void *signal_userdata;
	tdbus_method_call_f read_method_cb;
	void *method_userdata;
	tdbus_read_reply_f read_reply_cb;
	void *reply_userdata;
};

static void tdbus_dispatch_timeout(void *data, int fd, DBusTimeout *timeout,
                                   struct tdbus *bus);

static int tdbus_find_timeout_fd(struct tdbus *bus, DBusTimeout *timeout);

bool tdbus_write_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
                     va_list ap);

bool tdbus_read_itr(DBusSignatureIter *sitr, DBusMessageIter *itr,
                    va_list ap);

/*******************************************************************************
 * dbus watches
 ******************************************************************************/

static void
tdbus_toggle_watch(DBusWatch *watch, void *data)
{
	struct tdbus *bus = data;
	uint32_t mask = 0, flags;
	int fd;

	if (!bus->ch_watch_cb)
		return;

	fd = dbus_watch_get_unix_fd(watch);
	if (dbus_watch_get_enabled(watch)) {
		flags = dbus_watch_get_flags(watch);
		if (flags & DBUS_WATCH_READABLE)
			mask |= TDBUS_READABLE;
		if (flags & DBUS_WATCH_WRITABLE)
			mask |= TDBUS_WRITABLE;
	}
	bus->ch_watch_cb(bus->watch_userdata, fd, bus, mask, watch);
}

static dbus_bool_t
tdbus_add_watch(DBusWatch *watch, void *data)
{
	struct tdbus *bus = data;
	int fd;
	uint32_t mask = 0, flags;

	//there is nothing we can do here
	if (!bus->add_watch_cb)
		return FALSE;
	if (dbus_watch_get_enabled(watch)) {
		flags = dbus_watch_get_flags(watch);
		if (flags & DBUS_WATCH_READABLE)
			mask |= TDBUS_READABLE;
		if (flags & DBUS_WATCH_WRITABLE)
			mask |= TDBUS_WRITABLE;
	}
	fd = dbus_watch_get_unix_fd(watch);
	//In this callback we need to register this fd as some event callback
	bus->add_watch_cb(bus->watch_userdata, fd, bus, mask, watch);

	return TRUE;
}

static void
tdbus_remove_watch(DBusWatch *watch, void *data)
{
	struct tdbus *bus = data;
	int fd;

	if (!bus->rm_watch_cb)
		return;

	fd = dbus_watch_get_unix_fd(watch);
	bus->rm_watch_cb(bus->watch_userdata, fd, bus, watch);
}

void
tdbus_handle_watch(struct tdbus *bus, void *data)
{
	DBusTimeout *timeout = data;
	DBusWatch *watch = data;
	int timerfd = tdbus_find_timeout_fd(bus, timeout);

	if (timerfd > 0)
		tdbus_dispatch_timeout(data, timerfd, timeout, bus);
	else if (dbus_watch_get_enabled(watch))
		dbus_watch_handle(watch,
		                  dbus_watch_get_flags(watch));
}

/*******************************************************************************
 * dbus timeouts
 ******************************************************************************/
static bool
tdbus_init_timeouts(struct tdbus *bus)
{
	struct tdbus_timeout_record *records =
		malloc(sizeof(struct tdbus_timeout_record) * 16);
	if (!records)
		return false;
	//set records to -1 so they are invalid
	memset(records, -1, sizeof(struct tdbus_timeout_record) * 16);
	bus->timeouts = records;
	bus->timeouts_used = 0;
	bus->timeouts_allocated = 16;
	return true;
}

static inline void
tdbus_release_timeouts(struct tdbus *bus)
{
	if (bus->timeouts) {
		free(bus->timeouts);
		bus->timeouts_allocated = 0;
		bus->timeouts_used = 0;
	}
}

static bool
tdbus_add_timeout_record(struct tdbus *bus, int timerfd, DBusTimeout *timeout)
{
	//test if there is still slots inside
	if (bus->timeouts_used < bus->timeouts_allocated)
		goto insert_timeout;

	size_t new_size = bus->timeouts_allocated  * 2 *
		sizeof(struct tdbus_timeout_record);
	int counter = 0;

	struct tdbus_timeout_record *new_records =
		bus->timeouts;
	if ((new_records = realloc(bus->timeouts, new_size)) == NULL)
		return false;

	for (unsigned i = 0; i < bus->timeouts_used; i++) {
		struct tdbus_timeout_record *old_rec =
			bus->timeouts + i;
		struct tdbus_timeout_record *new_rec =
			new_records + counter;
		struct tdbus_timeout_record tmp = *old_rec;

		if (tmp.timerfd > 0 && tmp.timeout) {
			*new_rec  = tmp;
			counter++;
		}
	}
	bus->timeouts = new_records;
	bus->timeouts_used = counter;
	bus->timeouts_allocated *= 2;

insert_timeout:
	new_records = bus->timeouts + bus->timeouts_used;
	new_records->timeout = timeout;
	new_records->timerfd = timerfd;
	bus->timeouts_used += 1;

	return true;
}

static int
tdbus_find_timeout_fd(struct tdbus *bus, DBusTimeout *timeout)
{
	for (unsigned i = 0; i < bus->timeouts_used; i++)
		if ((bus->timeouts + i)->timeout == timeout)
			return (bus->timeouts + i)->timerfd;
	return 0;
}

static void
tdbus_rm_timeout_record(struct tdbus *bus, int timerfd)
{
	for (unsigned i = 0; i < bus->timeouts_used; i++)
		if ((bus->timeouts + i)->timerfd == timerfd) {
			(bus->timeouts+i)->timerfd = -1;
			(bus->timeouts+i)->timeout = NULL;
			break;
		}
}

static dbus_bool_t
tdbus_add_timeout(DBusTimeout *timeout, void *data)
{
	struct tdbus *bus = data;
	int64_t interval;
	int fd;
	struct itimerspec timespec = {
		{0,0},
		{0,0},
	};

	if (!bus->add_watch_cb)
		goto err_init_timer;
	//otherwise, create a timerfd to watch
	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (!fd)
		goto err_init_timer;
	if (timerfd_settime(fd, 0, &timespec, NULL))
		goto err_settime;

	if (dbus_timeout_get_enabled(timeout)) {
		interval = dbus_timeout_get_interval(timeout);
		timespec.it_value.tv_nsec = interval * 1000;
		timespec.it_value.tv_sec = 0;
		timespec.it_interval = timespec.it_value;

		if (timerfd_settime(fd, 0, &timespec, NULL))
			goto err_settime;
	}

	bus->add_watch_cb(bus->watch_userdata, fd, bus,
	                  TDBUS_READABLE, timeout);
	tdbus_add_timeout_record(bus, fd, timeout);
	dbus_timeout_set_data(timeout, bus->watch_userdata, NULL);

	return TRUE;
err_settime:
	close(fd);
err_init_timer:
	return FALSE;
}

static void
tdbus_remove_timeout(DBusTimeout *timeout, void *data)
{
	struct tdbus *bus = data;
	void *userdata = dbus_timeout_get_data(timeout);
	int timerfd = tdbus_find_timeout_fd(bus, timeout);

	if (!bus->rm_watch_cb)
		return;

	bus->rm_watch_cb(userdata, timerfd, bus, timeout);
	tdbus_rm_timeout_record(bus, timerfd);
}

static void
tdbus_toggle_timeout(DBusTimeout *timeout, void *data)
{
	struct tdbus *bus = data;
	int timerfd = tdbus_find_timeout_fd(bus, timeout);

	if (dbus_timeout_get_enabled(timeout)) {
		int64_t interval = dbus_timeout_get_interval(timeout);
		struct itimerspec timespec = {
			.it_value = {
				.tv_sec = 0,
				.tv_nsec = interval * 1000,
			},
			.it_interval = {
				.tv_sec = 0,
				.tv_nsec = interval * 1000,
			},
		};
		timerfd_settime(timerfd, 0, &timespec, NULL);
	}

}

static void
tdbus_dispatch_timeout(void *data, int timerfd, DBusTimeout *timeout,
                       struct tdbus *bus)
{
	uint64_t nhit;
	//read the timer first
	read(timerfd, &nhit, 8);
	//find the timer based on fd
	if (timeout && dbus_timeout_get_enabled(timeout))
		dbus_timeout_handle(timeout);
}

/*******************************************************************************
 * tdbus messenger
 ******************************************************************************/
static void
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
 * @brief handle message callback
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
	struct tdbus_method_call call = {
		.bus = bus,
		.user_data = bus->method_userdata,
		.message = &bus_msg,
	};
	struct tdbus_reply reply = {
		.bus = bus,
		.user_data = bus->reply_userdata,
		.message = &bus_msg,
	};

	tdbus_reader_from_message(message, &signal, &call, &reply);
	type = dbus_message_get_type(message);

	switch (type) {
	case DBUS_MESSAGE_TYPE_INVALID:
		return DBUS_HANDLER_RESULT_HANDLED;

	case DBUS_MESSAGE_TYPE_SIGNAL:
		read_ret = (bus->read_signal_cb) ?
			bus->read_signal_cb(&signal) : 0;
		break;

	case DBUS_MESSAGE_TYPE_METHOD_CALL:
		read_ret = (bus->is_server && bus->read_method_cb) ?
			bus->read_method_cb(&call) : 0;
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
tdbus_new(enum TDBUS_TYPE type, const char *address)
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
	bus->is_server = false;
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
	dbus_connection_flush(bus->conn);
	tdbus_release_timeouts(bus);
	dbus_connection_close(bus->conn);
	dbus_connection_unref(bus->conn);
	dbus_free(bus);
}

void
tdbus_set_nonblock(struct tdbus *bus, void *data,
                   tdbus_add_watch_f addf,
                   tdbus_ch_watch_f chf,
                   tdbus_rm_watch_f rmf)
{
	dbus_bool_t r;

	bus->add_watch_cb = addf;
	bus->ch_watch_cb = chf;
	bus->rm_watch_cb = rmf;
	bus->non_block = true;
	bus->watch_userdata = data;

	r = dbus_connection_set_watch_functions(bus->conn,
	                                        tdbus_add_watch,
	                                        tdbus_remove_watch,
	                                        tdbus_toggle_watch,
	                                        bus,
	                                        NULL);
	if (r != TRUE)
		goto err_set_func;
	r = dbus_connection_set_timeout_functions(bus->conn,
	                                          tdbus_add_timeout,
	                                          tdbus_remove_timeout,
	                                          tdbus_toggle_timeout,
	                                          bus,
	                                          NULL);
	if (r != TRUE)
		goto err_set_func;
	return;

err_set_func:
	dbus_connection_set_watch_functions(bus->conn, NULL, NULL,
	                                    NULL, NULL, NULL);
	dbus_connection_set_timeout_functions(bus->conn, NULL, NULL,
	                                      NULL, NULL, NULL);
	bus->add_watch_cb = NULL;
	bus->ch_watch_cb = NULL;
	bus->rm_watch_cb = NULL;
	bus->non_block = false;
	bus->watch_userdata = NULL;
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
                 tdbus_method_call_f method_reply, void *ud_mc,
                 tdbus_read_reply_f reply_reader, void *ud_rp)
{
	bus->signal_userdata = ud_sig;
	bus->read_signal_cb = sig_reader;

	bus->read_method_cb = method_reply;
	bus->method_userdata = ud_mc;

	bus->read_reply_cb = reply_reader;
	bus->reply_userdata = ud_rp;
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


#ifdef __cplusplus
}
#endif
