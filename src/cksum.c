/* vim: set ts=2 et sw=2 : */
/** @file cksum.c */
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

#include <t50_cksum.h>

/**
 * Calculates checksum.
 *
 * RFC 1071 compliant checksum routine.
 *
 * @param data Pointer to buffer.
 * @param length Length of the buffer.
 * @return 16 bits checksum.
 */
// FIX: Changed to 32 bit length 'cause it's faster!
uint16_t cksum ( void *data, uint32_t length )
{
  uint32_t sum;
  uint16_t *p = data;
  _Bool rem;

  sum = 0;
  rem = length & 1; // if there is a remaining byte this will be true.
  length >>= 1;     // lenth contains # of words.

  /* Accumulate all 16 bit words on buffer. */
  while ( length-- )
    sum += *p++;

  /* Is there a single byte remaining? */
  if ( rem )
    sum += * ( uint8_t * ) p;

  /* Accumulate 16 bits carry-outs.*/

  // FIX: Don't need the loop. A 16 MiB buffer full of 0xff will overflow the 32bit sum,
  //      but we're dealing with much smalled buffers.
  if ( sum > 0xffff )
  {
    sum = ( sum & 0xffff ) + ( sum >> 16 );
    sum += ( sum >> 16 );
  }

  return ~sum;
}
