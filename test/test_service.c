#include <stdio.h>
#include <stdbool.h>
#include <tdbus.h>

#include <sys/epoll.h>

static int epoll_fd = -1;

static int read_signal(const struct tdbus_signal *signal)
{
	char string[100];
	tdbus_read(signal->message, "s", string);
	return 0;
}

static int read_method(const struct tdbus_method_call *call)
{
	return 0;
}

int main(int argc, char *argv[])
{
	/* struct epoll_event events[32]; */
	struct tdbus *bus;
	/* void *watch_data; */
	/* int count = 0; */

	epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	bus = tdbus_new_server(SESSION_BUS, "org.taiwins");
	/* tdbus_set_nonblock(bus, NULL, */
	/*                    add_watch, change_watch, remove_watch); */
	tdbus_server_add_method(bus, "/org/taiwins/example", "org.taiwins.example", "s");

	tdbus_set_reader(bus, read_signal, NULL, read_method, NULL, NULL, NULL);

	while (true) {
		tdbus_dispatch_once(bus);
		/* count = epoll_wait(epoll_fd, events, 32, 100); */
		/* if (count < 0) */
		/*	break; */
		/* for (int i = 0; i < count; i++) { */
		/*	watch_data = events[i].data.ptr; */
		/*	tdbus_handle_watch(bus, watch_data); */
		/* } */
	}

	tdbus_delete(bus);
	return 0;

}
