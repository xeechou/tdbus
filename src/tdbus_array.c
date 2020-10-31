/*
 * tdbus_array.c - tdbus array implementation
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

#include <tdbus.h>
#include "tdbus_internal.h"

void
tdbus_array_init(struct tdbus_array *array)
{
	array->alloc = 0;
	array->size = 0;
	array->data = NULL;
}

void
tdbus_array_init_fixed(struct tdbus_array *array,
                       size_t alloc, void *data)
{
	array->alloc = alloc;
	array->size = 0;
	array->data = data;
}

void
tdbus_array_release(struct tdbus_array *array)
{
	if (array->data)
		dbus_free(array->data);
	array->data = NULL;
	array->size = 0;
	array->alloc = 0;

}

void *
tdbus_array_add(struct tdbus_array *array, size_t size)
{
	size_t alloc;
	void *data, *p;

	//here we make sure alloc is always no less than array->alloc
	if (array->alloc > 0)
		alloc = array->alloc;
	else
		alloc = 16;
	while (alloc < size + array->size)
		alloc *= 2;

	if (!array->data)
		data = dbus_malloc(alloc);
	else if (alloc > array->alloc)
		data = dbus_realloc(array->data, alloc);
	else
		data = array->data;
	if (!data)
		return NULL;

	array->data = data;
	array->alloc = alloc;
	p = array->data + array->size;
	array->size += size;

	return p;
}
