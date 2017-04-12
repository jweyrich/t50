/* vim: set ts=2 et sw=2 : */
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

#ifndef __CIDR_H__
#define __CIDR_H__

#include <stdint.h>
#include <netinet/in.h>
#include <t50_typedefs.h>

#define CIDR_MINIMUM 8
#define CIDR_MAXIMUM 32 // fix #7

/** @struct cidr
    T50 cidr structure. */
struct cidr
{
  uint32_t  hostid;                 /* hosts identifiers           */
  in_addr_t __1st_addr;             /* first IP address            */
};

struct cidr *config_cidr(const struct config_options * const __restrict__);

#endif
