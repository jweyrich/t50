/* vim: set ts=2 et sw=2 : */
/** @file igmp_help.c */
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
#include <linux/igmp.h>
#include <t50_modules.h>

/** IGMP options help. */
void igmp_help(void)
{
  printf("IGMP Options:\n"
         "    --igmp-type NUM           IGMPv1/v3 type                   (default 0x%x)\n"
         "    --igmp-code NUM           IGMPv1/v3 code                   (default 0)\n"
         "    --igmp-group ADDR         IGMPv1/v3 address                (default RANDOM)\n"
         "    --igmp-qrv NUM            IGMPv3 QRV                       (default RANDOM)\n"
         "    --igmp-suppress           IGMPv3 suppress router-side      (default OFF)\n"
         "    --igmp-qqic NUM           IGMPv3 QQIC                      (default RANDOM)\n"
         "    --igmp-grec-type NUM      IGMPv3 group record type         (default 1)\n"
         "    --igmp-sources NUM        IGMPv3 # of sources              (default 2)\n"
         "    --igmp-multicast ADDR     IGMPv3 group record multicast    (default RANDOM)\n"
         "    --igmp-address ADDR,...   IGMPv3 source address(es)        (default RANDOM)\n\n",
         IGMP_HOST_MEMBERSHIP_QUERY);
}

