/*
 * tdbus_watch.h - tdbus message header
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

#ifndef TDBUS_WATCHER_H
#define TDBUS_WATCHER_H

#include <stdbool.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct tdbus;

/**
 * dbus watchers
 */
typedef void (*tdbus_add_watch_f)(void *user_data, int unix_fd,
                                  struct tdbus *bus, uint32_t mask,
                                  void *watch_data);
typedef void (*tdbus_ch_watch_f)(void *user_data, int unix_fd,
                                 struct tdbus *bus, uint32_t mask,
                                 void *watch_data);
typedef void (*tdbus_rm_watch_f)(void *user_data, int unix_fd,
                                 struct tdbus *bus, void *watch_data);

typedef void (*tdbus_add_timeout_f)(void *user_data, int interval, bool enable,
                                    struct tdbus *bus, void *timeout_data);
typedef void (*tdbus_ch_timeout_f)(void *user_data, int interval,
                                   struct tdbus *bus, void *timeout_data);
typedef void (*tdbus_rm_timeout_f)(void *user_data, struct tdbus *bus,
                                   void *timeout_data);

/**
 * @brief set tdbus to work in the nonblock mode
 *
 * dbus mainloop intergration, the watches does not do anything useful, only
 * required for dbus to be non-block.
 *
 * In the watches, call @tdbus_handle_watch to process the dbus internals.
 */
void
tdbus_set_nonblock(struct tdbus *bus, void *data,
                   tdbus_add_watch_f addf, tdbus_ch_watch_f chf,
                   tdbus_rm_watch_f rmf,
                   tdbus_add_timeout_f addt, tdbus_ch_timeout_f cht,
                   tdbus_rm_timeout_f rmt);
void
tdbus_handle_watch(void *watch_data);

void
tdbus_watch_set_user_data(void *watch_data, void *user_data);

void *
tdbus_watch_get_user_data(void *watch_data);

void
tdbus_handle_timeout(void *timeout_data);

int
tdbus_timeout_gen_timerfd(void *timeout_data);

void
tdbus_timeout_reset_timer(void *timeout, int timerfd);

void
tdbus_timeout_set_user_data(void *timeout_data, void *user_data);

void *
tdbus_timeout_get_user_data(void *timeout_data);

/**
 * @brief dispatch the mainloop once, this is an idle run. I cant believe they
 * dont have polling
 */
void
tdbus_dispatch_once(struct tdbus *bus);



#ifdef __cplusplus
}
#endif

#endif /* EOF */
