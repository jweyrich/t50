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

#include <common.h>

uint8_t *packet = NULL;
size_t current_packet_size = 0;

/* NOTE: This routine shouldn't be inlined due to its compliexity. */
uint32_t NETMASK_RND(uint32_t foo)
{
  uint32_t t;

  if (foo != INADDR_ANY)
    t = foo;
  else
    t = ~(0xffffffffUL >> (8 + (random() % 23)));

  return htonl(t);
}

/* NOTE: Since VLAs are "dirty" allocations on stack frame, it's not a problem to use
   the technique below. */
void alloc_packet(size_t new_packet_size)
{
  void *p;

	/* Because 0 will free the buffer!!! */
  assert(new_packet_size != 0);

  if (new_packet_size > current_packet_size)
  {
    if ((p = realloc(packet, new_packet_size)) == NULL)
    {
      ERROR("Error reallocating packet buffer");
      exit(EXIT_FAILURE);
    }

    packet = (uint8_t *)p;
    current_packet_size = new_packet_size;
  }
}

/* Scan the list of modules, returning the number of itens in the list. */
int getNumberOfRegisteredModules(void)
{
	int n;
	modules_table_t *ptbl;

	for (n = 0, ptbl = mod_table; ptbl->func != NULL; ptbl++, n++);

	return n;
}

