/*
 * tdbus_message.h - tdbus message header
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

#ifndef TDBUS_MESSAGE_H
#define TDBUS_MESSAGE_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>

#include "tdbus_message_iter.h"

#ifdef __cplusplus
extern "C" {
#endif

struct tdbus;
struct tdbus_message;

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

void
tdbus_free_message(struct tdbus_message *message);


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
bool
tdbus_readv(const struct tdbus_message *msg, const char *format,
            va_list ap);

static inline bool
tdbus_read(const struct tdbus_message *msg,
           const char *format, ...)
{
	va_list ap;
	bool ret = true;

	va_start(ap, format);
	ret = tdbus_readv(msg, format, ap);
	va_end(ap);
	return ret;
}

bool
tdbus_read_with_iter(const struct tdbus_message *msg, const char *format,
                     struct tdbus_message_itr *itr);

/**
 * @brief writing a message
 */
bool
tdbus_writev(struct tdbus_message *message, const char *format, va_list ap);

static inline bool
tdbus_write(struct tdbus_message *msg, const char *format, ...)
{
	bool ret;
	va_list ap;

	va_start(ap, format);
	ret = tdbus_writev(msg, format, ap);
	va_end(ap);
	return ret;
}

bool
tdbus_write_with_itr(struct tdbus_message *msg, const char *format,
                     struct tdbus_message_itr *itr);

/**
 * @brief generate a method call message for writing,
 *
 * use tdbus_write to produce the content of the message
 */
struct tdbus_message *
tdbus_call_method(const char *dest, const char *path,
                  const char *interface, const char *method,
                  tdbus_read_reply_f reply, void *user_data);

/**
 * @brief generate a reply message on the server
 */
struct tdbus_message *
tdbus_reply_method(const struct tdbus_message *reply_to,
                   const char *err_name);

void
tdbus_send_message(struct tdbus *bus, struct tdbus_message *msg);

/**
 * @brief send message and wait for reply
 *
 * The message can only be a method call. The function returns false on erro
 * occurs. It also resues the @param msg for the reply.
 */
bool
tdbus_send_message_block(struct tdbus *bus, struct tdbus_message *msg,
                         struct tdbus_reply *reply);

#ifdef __cplusplus
}
#endif

#endif /* EOF */
