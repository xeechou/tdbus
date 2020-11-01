#include "tdbus_message.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include <tdbus.h>
#include <tdbus_message_iter.h>

static bool test_variant(struct tdbus *bus)
{
	struct tdbus_message_arg data = {
		.type = TDBUS_ARG_DOUBLE,
		.arg.d = 9.999,
	};
	struct tdbus_message_arg variant = {
		.type = TDBUS_ARG_VARIANT,
		.arg.variant.signature = "d",
		.arg.variant.arg = &data,
	};
	struct tdbus_message *msg = tdbus_call_method(
		"org.freedesktop.DBus", "/org/freedesktop/DBus",
		"org.freedesktop.DBus", "ListNames", NULL, NULL);

	if (!tdbus_write(msg, "ybdv", 'a', true, 10.0, variant))
		return false;

	struct tdbus_message_arg vread = {0};
	double d; bool tf; char c;

	if (!tdbus_read(msg, "ybdv", &c, &tf, &d, &vread))
		return false;

	tdbus_msg_done_variant(&vread);

	tdbus_free_message(msg);
	return true;
}

static bool test_basic(struct tdbus *bus)
{
	char b, *string = NULL;
	int ia, ib;
	struct tdbus_message *msg = tdbus_call_method(
		"org.freedesktop.DBus", "/org/freedesktop/DBus",
		"org.freedesktop.DBus", "ListNames", NULL, NULL);

	tdbus_write(msg, "ysii", 18, "hello world", 12829099, 1283222);
	tdbus_read(msg, "ysii", &b, &string, &ia, &ib);

	bool ret = b == 18 && (strcmp(string, "hello world") == 0) &&
		ia == 12829099 && ib == 1283222;
	free(string);
	tdbus_free_message(msg);
	return ret;
}

static bool test_array_basic(struct tdbus *bus)
{
	double doubles[4] = { 1.0f, 2.0f, 3.0f, 4.0f };
	double *wdoubles = NULL;
	int wi, n;
	char ca, cb;

	struct tdbus_message *msg2 = tdbus_call_method(
		"org.freedesktop.DBus", "/org/freedesktop/DBus",
		"org.freedesktop.DBus", "ListNames", NULL, NULL);
	tdbus_write(msg2, "iad(y)y", 18, 4, doubles, 32, 35);
	if (!tdbus_read(msg2, "iad(y)y", &wi, &n, &wdoubles, &ca, &cb))
		return false;

	bool ret = wi == 18 && n == 4 &&
		wdoubles[0] == 1.0f && wdoubles[1] == 2.0f &&
		wdoubles[2] == 3.0f && wdoubles[3] == 4.0f &&
		ca == 32 && cb == 35;
	free(wdoubles);
	tdbus_free_message(msg2);

	return ret;
}

static bool
test_array_complex(struct tdbus *bus)
{
	int n;
	struct tdbus_message_arg vdata[4] = {
		{.type = TDBUS_ARG_DOUBLE, .arg.d = 9.99,},
		{.type = TDBUS_ARG_INT32, .arg.i32 = 10},
		{.type = TDBUS_ARG_STRING, .arg.str = "hello"},
		{.type = TDBUS_ARG_UINT64, .arg.u64 = 69533},
	};
	struct tdbus_arg_dict_entry entries[4] = {
		{
			.key = {.type = TDBUS_ARG_STRING, .arg.str="e0"},
			.val = {
				.type = TDBUS_ARG_VARIANT,
				.arg.variant.signature = "d",
				.arg.variant.arg = &vdata[0],
			},
		},
		{
			.key = {.type = TDBUS_ARG_STRING, .arg.str="e1"},
			.val = {
				.type = TDBUS_ARG_VARIANT,
				.arg.variant.signature = "i",
				.arg.variant.arg = &vdata[1],
			},
		},
		{
			.key = {.type = TDBUS_ARG_STRING, .arg.str="e2"},
			.val = {
				.type = TDBUS_ARG_VARIANT,
				.arg.variant.signature = "s",
				.arg.variant.arg = &vdata[2],
			},
		},
		{
			.key = {.type = TDBUS_ARG_STRING, .arg.str="e3"},
			.val = {
				.type = TDBUS_ARG_VARIANT,
				.arg.variant.signature = "t",
				.arg.variant.arg = &vdata[3],
			},
		},
	}, *wentries;
	struct tdbus_message *msg2 = tdbus_call_method(
		"org.freedesktop.DBus", "/org/freedesktop/DBus",
		"org.freedesktop.DBus", "ListNames", NULL, NULL);
	if (!tdbus_write(msg2, "a{sv}", 4, entries))
		return false;
	if (!tdbus_read(msg2, "a{sv}", &n, &wentries))
		return false;
	bool ret = n == 4 && wentries[0].val.type == TDBUS_ARG_VARIANT &&
		wentries[1].val.type == TDBUS_ARG_VARIANT &&
		wentries[2].val.type == TDBUS_ARG_VARIANT &&
		wentries[3].val.type == TDBUS_ARG_VARIANT;

	for (int i = 0; i < 4; i++)
		tdbus_msg_done_dict_entry(&wentries[i]);
	free(wentries);

	tdbus_free_message(msg2);

	return ret;
}

static bool
test_empty(struct tdbus *bus)
{
	struct tdbus_message *msg2 = tdbus_call_method(
		"org.freedesktop.DBus", "/org/freedesktop/DBus",
		"org.freedesktop.DBus", "ListNames", NULL, NULL);
	if (!tdbus_write(msg2, ""))
		return false;
	if (!tdbus_read(msg2, ""))
		return false;
	tdbus_free_message(msg2);
	return true;
}

int main()
{
	struct tdbus *bus = tdbus_new(SYSTEM_BUS);

	if (!test_variant(bus))
		return -1;
	if (!test_basic(bus))
		return -1;
	if (!test_array_basic(bus))
		return -1;
	if (!test_array_complex(bus))
		return -1;
	if (!test_empty(bus))
		return -1;


	tdbus_delete(bus);

}
