/*
 *  T50 - Experimental Mixed Packet Injector
 *
 *  Copyright (C) 2010 - 2015 - T50 developers
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

/* Actual packet buffer. Allocated dynamically. */
void *packet = NULL;
size_t current_packet_size = 0;

/* "private" variable holding the number of modules. Use get_number_of_registered_modules() funcion to get it. */
static size_t number_of_modules = 0;

/* NOTE: This routine shouldn't be inlined due to its compliexity. */
uint32_t NETMASK_RND(uint32_t foo)
{
  uint32_t t;

  if (foo != INADDR_ANY)
    t = foo;
  else
    t = ~(~0U >> (8 + (RANDOM() % 23)));

  return htonl(t);
}

/* NOTE: Since VLAs are "dirty" allocations on stack frame, it's not a problem to use
   the technique below. 

   The function will reallocate memory only if the buffer isn't big enough to acomodate
   new_packet_size bytes. */
void alloc_packet(size_t new_packet_size)
{
  void *p;

	/* TEST: Because 0 will free the buffer!!! */
  assert(new_packet_size != 0);

  if (new_packet_size > current_packet_size)
  {
    if ((p = realloc(packet, new_packet_size)) == NULL)
    {
      ERROR("Error reallocating packet buffer");
      exit(EXIT_FAILURE);
    }

    packet = p;
    current_packet_size = new_packet_size;
  }
}

/* Scan the list of modules (ONCE!), returning the number of itens in the list. */
/* Function prototype moved to modules.h. */
/* NOTE: This function is here to not polute modules.c, where we keep only the modules definitions. */
size_t get_number_of_registered_modules(void)
{
	modules_table_t *ptbl;

  if (number_of_modules == 0)
	  for (ptbl = mod_table; ptbl->func != NULL; ptbl++, number_of_modules++);

	return number_of_modules;
}

#ifdef __HAVE_RDRAND__
uint32_t readrand(void)
{
  uint32_t d;

  /* Using assembly here is more reliable than using the intrinsic funcion! */
  __asm__ __volatile__ (
    "1:\n"
    "rdrand %0\n"
    "jnc 1b\n"         /* Carry flag is zero if RDRAND fails. 
                          No need to implement a failsafe here. RDRAND will work eventually. */
    : "=r" (d)
  );

  return d;
}
#endif
