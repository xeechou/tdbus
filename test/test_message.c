#include "tdbus_message_iter.h"
#include <dbus/dbus-shared.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <dbus/dbus.h>
#include <assert.h>

#include <tdbus.h>
#include <dbus/dbus.h>

static bool quit = false;


static int read_listNames(const struct tdbus_reply *reply)
{
	const char *bus_name = reply->sender;
	const char *interface = reply->interface;
	const char *err = reply->error_name;
	const char *signature = reply->signature;
	char **str_arr; int count;
	(void)(bus_name);
	(void)(interface);
	(void)(err);

	if (strcmp(signature, "as"))
		perror("signature not correct!\n");
	else {
		tdbus_read(reply->message, "as", &count, &str_arr);

		for (int i = 0; i < count; i++) {
			printf("%s\n", str_arr[i]);
			free(str_arr[i]);
		}
		free(str_arr);
	}

	quit = true;
	return 0;
}

int main()
{
	struct tdbus *bus = tdbus_new(SYSTEM_BUS);

	struct tdbus_message *msg1 = tdbus_call_method(
		DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
		DBUS_INTERFACE_DBUS, "ListNames", NULL, NULL);

	tdbus_write(msg1, "ysii", 18, "hello world", 12829099, 1283222);

	double doubles[4] = { 1.0f, 2.0f, 3.0f, 4.0f };
	struct tdbus_message *msg2 = tdbus_call_method(
		DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
		DBUS_INTERFACE_DBUS, "ListNames", NULL, NULL);
	tdbus_write(msg2, "iad(y)y", 18, 4, doubles, 32, 35);

	//this would not work
	struct tdbus_message *msg3 = tdbus_call_method(
		DBUS_SERVICE_DBUS, DBUS_PATH_DBUS,
		DBUS_INTERFACE_DBUS, "ListNames", read_listNames, NULL);

	double *ptr_doubles = NULL; int a, count; char c;
	//okay, now we read some message
	tdbus_read(msg2, "iad(y)y", &a, &count, &ptr_doubles, &c, &c);

	struct tdbus_message_itr *msg_itr = tdbus_msg_itr_new();

	tdbus_read_with_iter(msg2, "iad(y)y", msg_itr);
	tdbus_msg_itr_done(msg_itr);


	if (ptr_doubles)
		free(ptr_doubles);

	tdbus_free_message(msg1);
	tdbus_free_message(msg2);

	tdbus_send_message(bus, msg3);
	while(!quit) {
		tdbus_dispatch_once(bus);
	}

	tdbus_delete(bus);
}
