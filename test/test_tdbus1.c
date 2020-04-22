#include <stdio.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/epoll.h>

#include <tdbus.h>

static int epoll_fd = -1;

static void add_watch(void *user_data, int fd, struct tdbus *bus,
                      uint32_t mask, void *watch_data)
{
	int epoll_mask = 0;
	struct epoll_event ev;

	if (epoll_fd <= 0)
		return;
        if (mask & TDBUS_ENABLED) {
	        if (mask & TDBUS_READABLE)
		        epoll_mask |= EPOLLIN;
	        if (mask & TDBUS_WRITABLE)
		        epoll_mask |= EPOLLOUT;

	        ev.data.ptr = watch_data;
	        ev.events = epoll_mask;

	        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
        }
}

static void change_watch(void *user_data, int fd, struct tdbus *bus,
                         uint32_t mask, void *watch_data)
{
	struct epoll_event ev;
	int epoll_mask = 0;

	if (epoll_fd <= 0)
		return;

        if (mask & TDBUS_ENABLED) {
	        if (mask & TDBUS_READABLE)
		        epoll_mask |= EPOLLIN;
	        if (mask & TDBUS_WRITABLE)
		        epoll_mask |= EPOLLOUT;

	        ev.data.ptr = watch_data;
	        ev.events = epoll_mask;

	        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
        }
}

static void remove_watch(void *user_data, int fd, struct tdbus *bus,
                         void *watch_data)
{
	if (epoll_fd < 0)
		return;

	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}


int main(int argc, char *argv[])
{
	struct epoll_event events[32];
	struct tdbus *bus;
	void *watch_data;
	int count = 0;

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	bus = tdbus_new(SYSTEM_BUS);
	tdbus_set_nonblock(bus, NULL,
	                   add_watch, change_watch, remove_watch);

	for (int i = 0; i < 10; i++) {
		tdbus_dispatch_once(bus);
		count = epoll_wait(epoll_fd, events, 32, 200);
		if (count < 0)
			break;
		for (int i = 0; i < count; i++) {
			watch_data = events[i].data.ptr;
			tdbus_handle_watch(bus, watch_data);
		}
	}

	tdbus_delete(bus);
	return 0;
}
