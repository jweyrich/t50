/* vim: set ts=2 et sw=2 : */
/** @file shuffle.c */
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

#include <t50_defines.h>
#include <t50_shuffle.h>
#include <t50_randomizer.h>

// Knuth-Fisher-Yates (this one) is faster!
void shuffle ( uint32_t *p, size_t size )
{
  size_t i;

  while ( size )
  {
    i = RANDOM() % size--;
    swap ( p[size], p[i] );
  }
}

