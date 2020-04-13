/* vim: set ts=2 et sw=2 : */
/** @file memalloc.c */
/*
 *  T50 - Experimental Mixed Packet Injector
 *
 *  Copyright (C) 2010 - 2019 - T50 developers
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
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <t50_defines.h>
#include <t50_errors.h>

void  *packet = NULL;                   /* Actual packet buffer. Allocated dynamically. */
static size_t current_packet_size = 0;  /* Used by alloc_packet(). */

/**
 * Preallocates the packet buffer.
 *
 * The function will reallocate memory only if the buffer isn't big enough to acomodate
 * new_packet_size bytes. Using IPPROTO_T50, after the first 'round', the buffer will be
 * big enough to accomodate all packets and no reallocations will be made.
 *
 * @param size Size of the new 'global' packet buffer.
 */
void alloc_packet ( size_t new_packet_size )
{
  void *p;

  assert( new_packet_size );

  /* Realloc only ig the new packet size is greater than the old. */
  /* NOTE: Assume the condition is false the majority of time. */
  if ( new_packet_size > current_packet_size )
  {
    /* Tries to reallocate memory. */
    /* NOTE: Assume realloc will not fail. */
    if ( ! ( p = realloc ( packet, new_packet_size ) ) )
      fatal_error ( "Error reallocating packet buffer." );

    /* Only assign a new pointer if successfull */
    packet = p;
    current_packet_size = new_packet_size;
  }
}

void destroy_packet_buffer ( void )
{
  SAFE_FREE ( packet );
}
