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

/* Calculates checksum */
uint16_t cksum(void *data, size_t length)
{
  uint32_t sum;
  uint16_t *p = data;

  sum = 0;

  while (length > 1)
  {
    sum += *p++;
    length -= 2;
  }

  if (length)
    sum += *(unsigned char *)p;

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}


