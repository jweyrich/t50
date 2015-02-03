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

/* FIXME: Maybe there is bug here still... Must check. */
/* NOTE: This version of cksum is retired, for now, due to bugs. */
//uint16_t cksum(void *data, size_t length)
//{
//  uint64_t sum, oldsum, *p = data;
//  uint32_t t1, t2;
//  uint16_t t3, t4;
//
//  sum = oldsum = 0;
//
//  /* Sums 8 bytes at a time... */
//  while (length >= sizeof(uint64_t))
//  {
//    sum += *p++;
//    if (sum < oldsum) sum++;
//    oldsum = sum;
//    length -= sizeof(uint64_t);
//  }
//
//  /* Sums the remaing data, if any */
//  data = p;
//  if (length >= sizeof(uint32_t))
//  {
//    sum += *(uint32_t *)data;
//    if (sum < oldsum) sum++;
//    oldsum = sum;
//    length -= sizeof(uint32_t);
//    data += sizeof(uint32_t);
//  }
//
//  if (length >= sizeof(uint16_t))
//  {
//    sum += *(uint16_t *)data;
//    if (sum < oldsum) sum++;
//    oldsum = sum;
//    length -= sizeof(uint16_t);
//    data += sizeof(uint16_t);
//  }
//
//  if (length)
//  {
//    sum += *(uint8_t *)data;
//    if (sum < oldsum) sum++;
//  }
//
//  /* Fold down to 16 bits */
//  t1 = sum;
//  t2 = sum >> 32;
//  t1 += t2;
//  if (t1 < t2) t1++;
//
//  t3 = t1;
//  t4 = t1 >> 16;
//  t3 += t4;
//  if (t3 < t4) t3++;
//
//  return ~t3;
//}

/* This is the old version, implemented on RFC 1071. */
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
