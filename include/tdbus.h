/*
 * dbus.c - tdbus headers
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

#ifndef TDBUS_H
#define TDBUS_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct tdbus;
struct tdbus_message;


enum TDBUS_TYPE {
	SYSTEM_BUS,
	SESSION_BUS,
};

enum tdbus_event_mask {
	TDBUS_READABLE,
	TDBUS_WRITABLE,
};

enum tdbus_message_type {
	TDBUS_MSG_SIGNAL,
	TDBUS_MSG_CALL,
	TDBUS_MSG_REPLY,
	TDBUS_MSG_ERROR,
	TDBUS_MSG_MAX_ENUM,
};

struct tdbus_signal {
	const char *sender;
	const char *interface;
	const char *signature;
	const char *signal_name;

	struct tdbus_message *message;
	struct tdbus *bus;
	void *user_data;
};

struct tdbus_method_call {
	const char *interface;
	const char *method_name;
	const char *destination;
	const char *object_path;

	const char *sender;
	struct tdbus_message *message;
	struct tdbus *bus;
	void *user_data;
};

struct tdbus_reply {
	const char *sender;
	const char *interface;
	const char *method_name;
	const char *signature;
	const char *error_name;

	struct tdbus_message *message;
	struct tdbus *bus;
	void *user_data;
};

typedef int (*tdbus_read_signal_f)(const struct tdbus_signal *);
typedef int (*tdbus_read_call_f)(const struct tdbus_method_call *);
typedef int (*tdbus_read_reply_f)(const struct tdbus_reply *);

struct tdbus_call_answer {
	const char *interface;
	const char *method;
	const char *in_signature;
	const char *out_signature;
	tdbus_read_call_f reader;
};

struct tdbus *tdbus_new(enum TDBUS_TYPE type);

struct tdbus *tdbus_new_server(enum TDBUS_TYPE, const char *bus_name);

void tdbus_delete(struct tdbus *bus);

/* TODO: may get rid of this */
void tdbus_set_reader(struct tdbus *bus, tdbus_read_signal_f sig_reader,
                      void *ud_sig, tdbus_read_call_f method_reply,
                      void *ud_mc, tdbus_read_reply_f reply_reader,
                      void *ud_rp);

void tdbus_free_message(struct tdbus_message *message);

/**
 * @brief reading a message
 *
 * if you are a client, most likeyly you are reading a signal or a method
 * reply. Given you call them correctly. If you know the argument of message you
 * expect, call directly tdbus_read(v). Use tdbus_read(v) inside
 * @tdbus_read_signal_f or @tdbus_read_reply_f. You can verify the signature of
 * the incoming message with your reader to determine would that be what you
 * expect.
 *
 * If you are a server, you may expect clients are calling your methods,
 * implement @tdbus_read_call_f for that.
 *
 * Currently @tdbus_readv and @tdbus_writev only supports basic types.
 *
 */
void tdbus_readv(const struct tdbus_message *msg, const char *format,
                 va_list ap);

static inline void tdbus_read(const struct tdbus_message *msg,
                              const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	tdbus_readv(msg, format, ap);
	va_end(ap);
}

/**
 * @brief writing a message
 */
bool tdbus_writev(struct tdbus_message *message, const char *format, va_list ap);

static inline bool tdbus_write(struct tdbus_message *msg, const char *format, ...)
{
	bool ret;
	va_list ap;

	va_start(ap, format);
	ret = tdbus_writev(msg, format, ap);
	va_end(ap);
	return ret;
}

/**
 * @brief generate a method call message for writing,

 * use tdbus_write to produce the content of the message
 */
struct tdbus_message *tdbus_call_method(const char *dest, const char *path,
                                        const char *interface, const char *method,
                                        tdbus_read_reply_f reply, void *user_data);

/**
 * @brief generate a reply message on the server
 */
struct tdbus_message *tdbus_reply_method(const struct tdbus_message *reply_to,
                                         const char *err_name);

void tdbus_send_message(struct tdbus *bus, struct tdbus_message *msg);

/**
 * @brief adding methods and register the object path
 */
bool tdbus_server_add_methods(struct tdbus *bus, const char *obj_path,
                              unsigned int n_methods,
                              struct tdbus_call_answer *answers);

/**
 * dbus watchers
 */
typedef void (*tdbus_add_watch_f)(void *user_data, int unix_fd, struct tdbus *bus,
                                  uint32_t mask, void *watch_data);
typedef void (*tdbus_ch_watch_f)(void *user_data, int unix_fd, struct tdbus *bus,
                                 uint32_t mask, void *watch_data);
typedef void (*tdbus_rm_watch_f)(void *user_data, int unix_fd, struct tdbus *bus,
                                 void *watch_data);
/**
 * @brief set tdbus to work in the nonblock mode
 *
 * dbus mainloop intergration, the watches does not do anything useful, only
 * required for dbus to be non-block.
 *
 * In the watches, call @tdbus_handle_watch to process the dbus internals.
 */
void tdbus_set_nonblock(struct tdbus *bus, void *data,
                        tdbus_add_watch_f addf,
                        tdbus_ch_watch_f chf,
                        tdbus_rm_watch_f rmf);


void tdbus_handle_watch(struct tdbus *bus, void *watch_data);

/**
 * @brief dispatch the mainloop once, this is an idle run. I cant believe they
 * dont have polling
 */
void tdbus_dispatch_once(struct tdbus *bus);




#ifdef __cplusplus
}
#endif

#endif /* EOF */
