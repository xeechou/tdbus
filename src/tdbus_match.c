/*
 * tdbus_match.c - dbus matching implementation
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
#include <dbus/dbus.h>

#include <tdbus.h>
#include "tdbus_internal.h"


struct tdbus_signal_match {
	char *match;
	tdbus_read_signal_f reader;
	void *user_data;
};

void
tdbus_unmatch_signals(struct tdbus *bus)
{
	struct tdbus_signal_match *match;
	tdbus_array_for_each(match, &bus->matched_signals) {
		dbus_bus_remove_match(bus->conn, match->match, NULL);
		free(match->match);
	}

	tdbus_array_release(&bus->matched_signals);
}

bool
tdbus_match_signal(struct tdbus *bus,const char *sender,
                   const char *iface, const char *member,
                   const char *path, void *user_data,
                   tdbus_read_signal_f read_signal)
{
	struct tdbus_signal_match match, *copy;
	char *match_str = NULL;
	size_t match_len;
	const char *format = "type='signal',"
		"sender='%s',"
		"interface='%s',"
		"member='%s',"
		"path='%s'";

	if (!sender || !member || !iface || !path ||
	    !read_signal)
		return false;

	match_len = strlen(sender) + strlen(member) +
		strlen(iface) + strlen(path) + strlen(format);
	match_str = malloc(match_len + 1);
	if (!match_str)
		return false;

	sprintf(match_str, format, sender, iface, member, path);

	match.reader = read_signal;
	match.user_data = user_data;
	match.match = match_str;

	copy = tdbus_array_add(&bus->matched_signals, sizeof(match));
	if (!copy) {
		free(match_str);
		return false;
	}
	memcpy(copy, &match, sizeof(match));

	dbus_bus_add_match(bus->conn, "type='signal',"
	                   "sender='%s',"
	                   "interface='%s',"
	                   "member='%s',"
	                   "path='%s'", NULL);

	return true;

}

DBusHandlerResult
tdbus_handle_signal(struct tdbus *bus, struct tdbus_signal *signal)
{
	struct tdbus_signal_match *match;
	const char *path, *iface, *member, *sender;
	const char *format = "type='signal',"
		"sender='%s',"
		"interface='%s',"
		"member='%s',"
		"path='%s'";

	tdbus_array_for_each(match, &bus->matched_signals) {
		sscanf(match->match, format, &sender, &iface,
		       &member, &path);
		if (!strcmp(signal->sender, sender) &&
		    !strcmp(signal->interface, iface) &&
		    !strcmp(signal->signal_name, member)) {
			signal->user_data = match->user_data;
			match->reader(signal);
			return DBUS_HANDLER_RESULT_HANDLED;
		}
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
