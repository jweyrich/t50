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

#ifndef __MODULES_INCLUDED__
#define __MODULES_INCLUDED__

#include <typedefs.h>
#include <config.h>

/* Purpose-built protocol libraries to be used by T50 modules */
#include <protocol/ip.h>
#include <protocol/egp.h>
#include <protocol/gre.h>
#include <protocol/rip.h>
#include <protocol/igmp.h>
#include <protocol/ospf.h>
#include <protocol/rsvp.h>
#include <protocol/eigrp.h>
#include <protocol/tcp_options.h>
/* NOTE: Insert your new protocol header here and change the modules table @ modules.c. */

/* NOTE: Specific for modules definitions. Placed here, instead of defines.h. */
typedef struct {
	int protocol_id;
	char *acronym;
  char *description;
  int (*func)(const socket_t, const struct config_options *);
} modules_table_t;

#define BEGIN_MODULES_TABLE modules_table_t mod_table[] = {
#define END_MODULES_TABLE { 0, NULL, NULL, NULL } };

#define MODULE_ENTRY(id,acronym,descr,func) { (id), acronym, descr, func },

extern modules_table_t mod_table[];

extern int getNumberOfRegisteredModules(void);

/* Modules functions prototypes. */
extern int icmp  (const socket_t, const struct config_options *);
extern int igmpv1(const socket_t, const struct config_options *);
extern int igmpv3(const socket_t, const struct config_options *);
extern int tcp   (const socket_t, const struct config_options *);
extern int egp   (const socket_t, const struct config_options *);
extern int udp   (const socket_t, const struct config_options *);
extern int ripv1 (const socket_t, const struct config_options *);
extern int ripv2 (const socket_t, const struct config_options *);
extern int dccp  (const socket_t, const struct config_options *);
extern int rsvp  (const socket_t, const struct config_options *);
extern int ipsec (const socket_t, const struct config_options *);
extern int eigrp (const socket_t, const struct config_options *);
extern int ospf  (const socket_t, const struct config_options *);
/* --- add yours here --- */

#endif
