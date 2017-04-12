/* vim: set ts=2 et sw=2 : */
/** @file eigrp_help.c */
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

/** EIGRP help. */
void eigrp_help(void)
{
  printf("EIGRP Options:\n"
         "    --eigrp-opcode NUM        EIGRP opcode                     (default %d)\n"
         "    --eigrp-flags NUM         EIGRP flags                      (default RANDOM)\n"
         "    --eigrp-sequence NUM      EIGRP sequence #                 (default RANDOM)\n"
         "    --eigrp-acknowledge NUM   EIGRP acknowledgment #           (default RANDOM)\n"
         "    --eigrp-as NUM            EIGRP autonomous system          (default RANDOM)\n"
         "    --eigrp-type NUM          EIGRP type                       (default %d)\n"
         "    --eigrp-length NUM        EIGRP length                     (default NONE)\n"
         "    --eigrp-k1 NUM            EIGRP parameter K1 value         (default 1)\n"
         "    --eigrp-k2 NUM            EIGRP parameter K2 value         (default 0)\n"
         "    --eigrp-k3 NUM            EIGRP parameter K3 value         (default 1)\n"
         "    --eigrp-k4 NUM            EIGRP parameter K4 value         (default 0)\n"
         "    --eigrp-k5 NUM            EIGRP parameter K5 value         (default 0)\n"
         "    --eigrp-hold NUM          EIGRP parameter hold time        (default 360)\n"
         "    --eigrp-ios-ver NUM.NUM   EIGRP IOS release version        (default 12.4)\n"
         "    --eigrp-rel-ver NUM.NUM   EIGRP PROTO release version      (default 1.2)\n"
         "    --eigrp-next-hop ADDR     EIGRP [in|ex]ternal next-hop     (default RANDOM)\n"
         "    --eigrp-delay NUM         EIGRP [in|ex]ternal delay        (default RANDOM)\n"
         "    --eigrp-bandwidth NUM     EIGRP [in|ex]ternal bandwidth    (default RANDOM)\n"
         "    --eigrp-mtu NUM           EIGRP [in|ex]ternal MTU          (default 1500)\n"
         "    --eigrp-hop-count NUM     EIGRP [in|ex]ternal hop count    (default RANDOM)\n"
         "    --eigrp-load NUM          EIGRP [in|ex]ternal load         (default RANDOM)\n"
         "    --eigrp-reliability NUM   EIGRP [in|ex]ternal reliability  (default RANDOM)\n"
         "    --eigrp-daddr ADDR/CIDR   EIGRP [in|ex]ternal address(es)  (default RANDOM)\n"
         "    --eigrp-src-router ADDR   EIGRP external source router     (default RANDOM)\n"
         "    --eigrp-src-as NUM        EIGRP external autonomous system (default RANDOM)\n"
         "    --eigrp-tag NUM           EIGRP external arbitrary tag     (default RANDOM)\n"
         "    --eigrp-proto-metric NUM  EIGRP external protocol metric   (default RANDOM)\n"
         "    --eigrp-proto-id NUM      EIGRP external protocol ID       (default 2)\n"
         "    --eigrp-ext-flags NUM     EIGRP external flags             (default RANDOM)\n"
         "    --eigrp-address ADDR      EIGRP multicast sequence address (default RANDOM)\n"
         "    --eigrp-multicast NUM     EIGRP multicast sequence #       (default RANDOM)\n"
         "    --eigrp-authentication    EIGRP authentication included    (default OFF)\n"
         "    --eigrp-auth-key-id NUM   EIGRP authentication key ID      (default 1)\n\n",
         EIGRP_OPCODE_UPDATE,
         EIGRP_TYPE_INTERNAL);
}

