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

#include <common.h>

/* NOTE: A simple way to define the protocols table!

  To add a procotol, insert the proper header file on common.h (ex: protocol/xpto.h),
  change the Makefile, add a MODULE_ENTRY, modify config.c and usage.c and compile. That's it! */
BEGIN_MODULES_TABLE
           /* ( proto,        acronym,  description,                                  function ) */
  MODULE_ENTRY(IPPROTO_ICMP,  "ICMP",   "Internet Control Message Protocol",          icmp)
  MODULE_ENTRY(IPPROTO_IGMP,  "IGMPv1", "Internet Group Message Protocol v1",         igmpv1)
  MODULE_ENTRY(IPPROTO_IGMP,  "IGMPv3", "Internet Group Message Protocol v3",         igmpv3)
  MODULE_ENTRY(IPPROTO_TCP,   "TCP",    "Transmission Control Protocol",              tcp)
  MODULE_ENTRY(IPPROTO_EGP,   "EGP",    "Exterior Gateway Protocol",                  egp)
  MODULE_ENTRY(IPPROTO_UDP,   "UDP",    "User Datagram Protocol",                     udp)
  MODULE_ENTRY(IPPROTO_UDP,   "RIPv1",  "Routing Internet Protocol v1",               ripv1)
  MODULE_ENTRY(IPPROTO_UDP,   "RIPv2",  "Routing Internet Protocol v2",               ripv2)
  MODULE_ENTRY(IPPROTO_DCCP,  "DCCP",   "Datagram Congestion Control Protocol",       dccp)
  MODULE_ENTRY(IPPROTO_RSVP,  "RSVP",   "Resource Reservation Protocol",              rsvp)
  MODULE_ENTRY(IPPROTO_AH,    "IPSEC",  "Internet Security Protocl (AH/ESP)",         ipsec)
  MODULE_ENTRY(IPPROTO_EIGRP, "EIGRP",  "Enhanced Interior Gateway Routing Protocol", eigrp)
  MODULE_ENTRY(IPPROTO_OSPF,  "OSPF",   "Open Shortest Path First",                   ospf)
END_MODULES_TABLE
