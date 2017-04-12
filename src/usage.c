/* vim: set ts=2 et sw=2 : */
/** @file usage.c */
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
#include <stdlib.h>
#include <configuration.h>
#include <t50_help.h>

void show_version(void)
{
  puts("T50 Experimental Mixed Packet Injector Tool " VERSION "\n"
       "Originally created by Nelson Brito <nbrito@sekure.org>\n"
       "Previously maintained by Fernando Mercês <fernando@mentebinaria.com.br>\n"
       "Maintained by Frederico Lamberti Pissarra <fredericopissarra@gmail.com>");
}

/* Help and usage message */
void usage(void)
{
  show_version();

  puts("\nUsage: t50 <host[/cidr]> [options]");

  general_help();
  gre_help();
  tcp_udp_dccp_help();
  tcp_help();
  ip_help();
  icmp_help();
  egp_help();
  rip_help();
  dccp_help();
  rsvp_help();
  ipsec_help();
  eigrp_help();
  ospf_help();

  puts("Some considerations while running this program:\n"
       " 1. There is no limitation of using as many options as possible.\n"
       " 2. Report " PACKAGE " bugs at " PACKAGE_URL ".\n"
       " 3. Some header fields with default values MUST be set to \'0\' for RANDOM.\n"
       " 4. Mandatory arguments to long options are mandatory for short options too.\n"
       " 5. Be nice when using " PACKAGE ", the author DENIES its use for DoS/DDoS purposes.\n"
       " 6. Running " PACKAGE " with \'--protocol T50\' option sends ALL protocols sequentially.");

  exit(EXIT_FAILURE);
}

