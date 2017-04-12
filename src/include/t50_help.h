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

#ifndef __HELP_INCLUDED__
#define __HELP_INCLUDED__

/* Add usage function interface here.
   Add usage function definition for protocol at src/help/ directory.
   Change Makefile and src/usage.c. */
void general_help(void);
void gre_help(void);
void tcp_udp_dccp_help(void);
void tcp_help(void);
void ip_help(void);
void icmp_help(void);
void egp_help(void);
void rip_help(void);
void dccp_help(void);
void rsvp_help(void);
void ipsec_help(void);
void eigrp_help(void);
void ospf_help(void);

void show_version(void); /* Prints version info. */
void usage(void);        /* Prints usage message */

#endif
