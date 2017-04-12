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
uint16_t cksum(void *data, size_t length)
{
  uint32_t sum;
  uint16_t *p = data;
  int rem;

  sum = 0;
  rem = length & 1; // if there is a remaining byte this will be true.
  length /= 2;      // lenth contains # of words.

  /* Accumulate all 16 bit words on buffer. */
  while (length--)
    sum += *p++;

  /* Is there a single byte remaining? */
  if (rem)
    sum += *(unsigned char *)p;

  /* Accumulate 16 bits carry-outs.*/
  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}
/*
  This could be implemented (x86-64) as:

  cksum:
    xor eax,eax
    mov ecx,esi
    shr ecx,1
  .loop:
    jz  .loop_end
    mov bx,[rdi]
    add ax,bx
    adc ax,0
    add rdi,2
    dec ecx
    jmp .loop
  .loop_end:
    test esi,1
    jz  .end
    movzx bx,byte [rdi]
    add ax,bx
    adc ax,0
  .end:
    ret    
*/
