/* vim: set ts=2 et sw=2 : */
/** @file ip_help.c */
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

#include <stdio.h>
#include <t50_modules.h>

/** IP options help. */
void ip_help(void)
{
  printf("IP Options:\n"
         " -s,--saddr ADDR              IP source IP address             (default RANDOM)\n"
         "    --tos NUM                 IP type of service               (default 0x%x)\n"
         "    --id NUM                  IP identification                (default RANDOM)\n"
         "    --frag-offset NUM         IP fragmentation offset          (default 0)\n"
         "    --ttl NUM                 IP time to live                  (default 255)\n"
         "    --protocol PROTO          IP protocol                      (default TCP)\n\n",
         IPTOS_PREC_IMMEDIATE);
}

