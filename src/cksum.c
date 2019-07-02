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
 * FIXED: last implementation was WRONG... I can't find any faster way to do this!
 *        Yet... There was another error that didn't consider BIG ENDIAN machines...
 *        Note to myself: Don't mess with this routine again!
 */
uint16_t cksum ( void *data, uint32_t length )
{
  uint16_t *ptr;
  uint32_t sum;

  sum = 0;
  ptr = data;  
  while ( length > 1 )
  {
    sum += *ptr++;
    length -= 2;
  }

  // if there is any additional bytes remaining...
  if ( length > 0 )
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
   sum += (uint16_t)(*(uint8_t *)ptr) << 8;   // last byte must be
                                              // aligned to upper 8 bits.
#else
   sum += *(uint8_t *)ptr;
#endif

  // Add carry-outs...
  while ( sum >> 16 )
    sum = ( sum & 0xffffU ) + ( sum >> 16 );

  // NOTE: Let the caller put this in network order, if necessary!
  return ~sum;
}
