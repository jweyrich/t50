/* vim: set ts=2 et sw=2 : */
/** @file icmp_help.c */
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
#include <linux/icmp.h>
#include <t50_modules.h>

/** ICMP options help. */
void icmp_help(void)
{
  printf("ICMP Options:\n"
         "    --icmp-type NUM           ICMP type                        (default %d)\n"
         "    --icmp-code NUM           ICMP code                        (default 0)\n"
         "    --icmp-gateway ADDR       ICMP redirect gateway            (default RANDOM)\n"
         "    --icmp-id NUM             ICMP identification              (default RANDOM)\n"
         "    --icmp-sequence NUM       ICMP sequence #                  (default RANDOM)\n\n",
         ICMP_ECHO);
}

