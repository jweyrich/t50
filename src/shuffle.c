/* vim: set ts=2 et sw=2 : */
/** @file shuffle.c */
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

#include <t50_defines.h>
#include <t50_shuffle.h>
#include <t50_randomizer.h>

// NOTE: It is safe to use uint32_t instead of uint32_t 'cause
//       the index buffer will never be greater than the number
//       of available protocols.
void shuffle(uint32_t *p, uint32_t size)
{
  uint32_t i, j;

  for (i = 0; i < (size - 2); i++)
  {
    // NOTE: This routine will be called once each 'size'
    //       main loop iterations. This division will not
    //       slow things down very much...
    j = (RANDOM() % (size - i)) + i;
    swap(p[i], p[j]);
  }
}

