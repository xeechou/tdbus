#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <tdbus.h>
#include <stdlib.h>
#include <errno.h>

#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/types.h>

static int epoll_fd = -1;
static int TIMERFD_COUNT = 0;
static struct tfd_data {int fd; void *data;} TIMERFDS[1024] = {0};

static char *const exec_argv[] = {
	"--session",
	"--type=method_call",
	"--print-reply",
	"--dest=org.tdbus",
	"/org/tdbus",
	"org.freedesktop.DBus.Introspectable.Introspect"
};

static void
fork_exec()
{
	int  pid;
	pid = fork();
	if (pid == 0) {
		sleep(1);
		execvp("dbus-send", exec_argv);
	} else if (pid < 0) { //parent
		//some error occured.
		fprintf(stderr, "error in fork!!\n");
		exit(-1);
	}
}

/******************************************************************************
 * watchers
 *****************************************************************************/

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

/*****************************************************************************/

static int read_method(const struct tdbus_method_call *call)
{
	return 0;
}

int main(int argc, char *argv[])
{
	struct epoll_event events[32];
	struct tdbus *bus;
	void *watch_data;
	int count = 0, status = 0, pid, succeed = 0;
	int fd;

	struct tdbus_call_answer answer = {
		.interface = "org.tdbus.example",
		.method = "Ping",
		.in_signature = "s",
		.out_signature = "s",
		.reader = read_method,
	};

	struct tdbus_call_answer answer1 = {
		.interface = "org.tdbus.exmaple1",
		.method = "Echo",
		.in_signature = "s",
		.out_signature = "s",
		.reader = read_method,
	};

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	bus = tdbus_new_server(SESSION_BUS, "org.tdbus");
	tdbus_set_nonblock(bus, NULL, add_watch, change_watch, remove_watch,
	                   add_timeout, change_timeout, close_timeout);

	tdbus_server_add_methods(bus, "/org/tdbus", 1, &answer);
	tdbus_server_add_methods(bus, "/org/tdbus1", 1, &answer1);

	fork_exec();
	//alright, I have a
	for (int i = 0; i < 2000; i++) {
		tdbus_dispatch_once(bus);
		count = epoll_wait(epoll_fd, events, 32, 10);
		printf("the count is %d\n", count);
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
		while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
			if (!WIFEXITED(status))
				fprintf(stderr, "errno in child");
			else {
				succeed = 1;
				goto out;
			}
		}
	}
out:
	tdbus_delete(bus);
	if (succeed)
		return 0;
	else
		return -1;

}
