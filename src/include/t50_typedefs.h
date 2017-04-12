/* vim: set ts=2 et sw=2 : */
/*
 *  T50 - Experimental Mixed Packet Injector
 *
 *  Copyright (C) 2010 - 2014 - T50 developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __TYPEDEFS_INCLUDED__
#define __TYPEDEFS_INCLUDED__

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

/* Data types */
typedef int threshold_t;  /* FIX: If we need more than 2147483648 packets sent,
                                  this type can be changed to int64_t. */

/**
 * Union used to ease buffer pointer manipulation.
 *
 * This will help with pointer arithmetic. When we have to point to the next
 * field, on the packet buffer.
 *
 * Since an address have a fixed size, we have a generic pointer (void *) and
 * pointers to other types. When incrementing 'dword_ptr' on this union, we are
 * adding 4 to the pointer, for instance.
 */
typedef union
{
  void      *ptr;
  uint8_t   *byte_ptr;
  uint16_t  *word_ptr;
  uint32_t  *dword_ptr;
  in_addr_t *inaddr_ptr;
  uint64_t  *qword_ptr;
} memptr_t;

#endif
