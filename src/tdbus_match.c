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
	char *sender, *iface, *member, *path;
	size_t len;
	tdbus_read_signal_f reader;
	void *user_data;
};

#define MATCH_HEADER "type='signal'"
#define MATCH_SENDER "sender='%s'"
#define MATCH_IFACE  "interface='%s'"
#define MATCH_MEMBR  "member='%s'"
#define MATCH_PATH   "path='%s'"

static const char *MATCH_FMT = MATCH_HEADER ","
	MATCH_SENDER "," MATCH_IFACE "," MATCH_MEMBR "," MATCH_PATH;

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

static void
tdbus_set_match_info(struct tdbus_signal_match *match,
                     char *match_str, const char *sender,
                     const char *iface, const char *member,
                     const char *path)
{
	const char *samples[4] = {sender, iface, member, path};
	char **comps[4] = {&match->sender, &match->iface, &match->member,
		&match->path};

	for (int i = 0; i < 4; i ++) {
		size_t len = strlen(samples[i]);

		*comps[i] = strstr(match_str, samples[i]);
		assert(comps[i]);
		*(*comps[i] + len) = '\0'; //end of component
		match_str = *comps[i] + len + 1; //new match place
	}
}

TDBUS_EXPORT bool
tdbus_match_signal(struct tdbus *bus,const char *sender,
                   const char *iface, const char *member,
                   const char *path, void *user_data,
                   tdbus_read_signal_f read_signal)
{
	bool ret = true;
	struct tdbus_signal_match *copy;
	char *match_str = NULL;
	size_t match_len;
	DBusError dbus_err;

	if (!sender || !member || !iface || !path ||
	    !read_signal)
		return false;

	match_len = strlen(sender) + strlen(member) +
		strlen(iface) + strlen(path) + strlen(MATCH_FMT);
	match_str = malloc(match_len + 1);
	if (!match_str)
		return false;

	sprintf(match_str, MATCH_FMT, sender, iface, member, path);

        //add match first
	dbus_error_init(&dbus_err);
	dbus_bus_add_match(bus->conn, match_str, &dbus_err);
	ret = tdbus_handle_error(bus, TDBUS_LOG_ERRO, __FUNCTION__,
	                         &dbus_err);
	dbus_error_free(&dbus_err);
	if (!ret) {
		free(match_str);
		return false;
	}
	//add it to our array
	copy = tdbus_array_add(&bus->matched_signals, sizeof(*copy));
	if (!copy) {
		dbus_bus_remove_match(bus->conn, match_str, NULL);
		free(match_str);
		return false;
	}
	copy->reader = read_signal;
	copy->user_data = user_data;
	copy->match = match_str;
	copy->len = match_len+1;
	tdbus_set_match_info(copy, match_str, sender, iface, member, path);

	return true;
}

DBusHandlerResult
tdbus_handle_signal(struct tdbus *bus, struct tdbus_signal *signal)
{
	struct tdbus_signal_match *match;


	tdbus_array_for_each(match, &bus->matched_signals) {

		if (!strcmp(signal->sender, match->sender) &&
		    !strcmp(signal->interface, match->iface) &&
		    !strcmp(signal->signal_name, match->member)) {
			signal->user_data = match->user_data;
			match->reader(signal);
			return DBUS_HANDLER_RESULT_HANDLED;
		}
	}
	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}
