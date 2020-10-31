#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <unistd.h>
#include <sys/epoll.h>

#include <tdbus.h>

static int epoll_fd = -1;
static int TIMERFD_COUNT = 0;
static struct tfd_data {int fd; void *data;} TIMERFDS[1024] = {0};

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

static void add_timeout(void *user_data, int interval, bool enabled,
                        struct tdbus *bus, void *timeout)
{
	int timerfd;
	int epoll_mask = EPOLLIN;
	struct epoll_event ev;
	intptr_t ptr;

	if (epoll_fd <= 0)
		return;
	if (enabled) {
		timerfd = tdbus_timeout_gen_timerfd(timeout);
		if (timerfd < 0)
			return;
		ptr = timerfd;
		tdbus_timeout_set_user_data(timeout, (void *)ptr);

		ev.data.ptr = timeout;
		ev.events = epoll_mask;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timerfd, &ev);
		TIMERFDS[TIMERFD_COUNT++] =
			(struct tfd_data){ timerfd, timeout};

	}
}

static void change_timeout(void *user_data, int interval, struct tdbus *bus,
                           void *timeout)
{
	struct epoll_event ev;
	int epoll_mask = EPOLLIN;
	intptr_t ptr = (intptr_t)tdbus_timeout_get_user_data(timeout);
	int timerfd = ptr;

	if (epoll_fd <= 0 || timerfd < 0)
		return;
	tdbus_timeout_reset_timer(timeout, timerfd);

	ev.data.ptr = timeout;
	ev.events = epoll_mask;

	epoll_ctl(epoll_fd, EPOLL_CTL_MOD, timerfd, &ev);
}

static void close_timeout(void *user_data, struct tdbus *bus, void *timeout)
{
	intptr_t ptr = (intptr_t)tdbus_timeout_get_user_data(timeout);
	int timerfd = ptr;

	if (epoll_fd < 0 || timerfd < 0)
		return;
	epoll_ctl(epoll_fd, EPOLL_CTL_DEL, timerfd, NULL);
	close(timerfd);
}

static int istimerfd(void *data)
{
	for (int i = 0; i < TIMERFD_COUNT; i++) {
		if (TIMERFDS[i].data == data)
			return TIMERFDS[i].fd;
	}
	return -1;
}

int main(int argc, char *argv[])
{
	struct epoll_event events[32];
	struct tdbus *bus;
	void *watch_data;
	int count = 0;
	int fd;

	memset(TIMERFDS, -1, sizeof(TIMERFDS));

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	bus = tdbus_new(SYSTEM_BUS);
	tdbus_set_nonblock(bus, NULL, add_watch, change_watch, remove_watch,
	                   add_timeout, change_timeout, close_timeout);

	for (int i = 0; i < 10; i++) {
		tdbus_dispatch_once(bus);
		count = epoll_wait(epoll_fd, events, 32, 200);
		if (count < 0)
			break;
		for (int i = 0; i < count; i++) {
			watch_data = events[i].data.ptr;
			if ((fd = istimerfd(watch_data)) >= 0) {
				uint64_t nhit;
				read(fd, &nhit, 8);
				tdbus_handle_timeout(watch_data);
			} else {
				tdbus_handle_watch(watch_data);
			}
		}
	}

	tdbus_delete(bus);
	return 0;
}
