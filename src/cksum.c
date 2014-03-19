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

/* Calculates checksum */
/* This function is 5 times faster than the "official" rfc 1071 implementation (and shortter too!). */
uint16_t cksum(void *data, size_t length)
{
  uint64_t sum, *p = data;
  uint32_t t1, t2;
  uint16_t t3, t4;

  sum = 0;

  /* Sums 8 bytes at a time... */
  while (length >= sizeof(uint64_t))
  {
    uint64_t s = *p++;
    sum += s;
    if (sum < s) sum++;
    length -= sizeof(uint64_t);
  }

  /* Sums the remaing data, if any */
  data = p;
  if (length >= sizeof(uint32_t))
  {
    uint32_t s = *(uint32_t *)data;
    sum += s;
    if (sum < s) sum++;
    length -= sizeof(uint32_t);
    data += sizeof(uint32_t);
  }

  if (length >= sizeof(uint16_t))
  {
    uint16_t s = *(uint16_t *)data;
    sum += s;
    if (sum < s) sum++;
    length -= sizeof(uint16_t);
    data += sizeof(uint16_t);
  }

  if (length)
  {
    uint8_t s = *(uint8_t *)data;
    sum += s;
    if (sum < s) sum++;
  }

  /* Fold down to 16 bits */
  t1 = sum;
  t2 = sum >> 32;
  t1 += t2;
  if (t1 < t2) t1++;

  t3 = t1;
  t4 = t1 >> 16;
  t3 += t4;
  if (t3 < t4) t3++;

  return ~t3;
}
