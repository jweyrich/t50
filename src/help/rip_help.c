/* vim: set ts=2 et sw=2 : */
/** @file rip_help.c */
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
#include <sys/socket.h>
#include <t50_modules.h>

/** RIP options help. */
void rip_help(void)
{
  printf("RIP Options:\n"
         "    --rip-command NUM         RIPv1/v2 command                 (default 2)\n"
         "    --rip-family NUM          RIPv1/v2 address family          (default %d)\n"
         "    --rip-address ADDR        RIPv1/v2 router address          (default RANDOM)\n"
         "    --rip-metric NUM          RIPv1/v2 router metric           (default RANDOM)\n"
         "    --rip-domain NUM          RIPv2 router domain              (default RANDOM)\n"
         "    --rip-tag NUM             RIPv2 router tag                 (default RANDOM)\n"
         "    --rip-netmask ADDR        RIPv2 router subnet mask         (default RANDOM)\n"
         "    --rip-next-hop ADDR       RIPv2 router next hop            (default RANDOM)\n"
         "    --rip-authentication      RIPv2 authentication included    (default OFF)\n"
         "    --rip-auth-key-id NUM     RIPv2 authentication key ID      (default 1)\n"
         "    --rip-auth-sequence NUM   RIPv2 authentication sequence #  (default RANDOM)\n\n",
         AF_INET);
}

