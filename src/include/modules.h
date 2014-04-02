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
  module_func_ptr_t func;
} modules_table_t;

#define BEGIN_MODULES_TABLE modules_table_t mod_table[] = {
#define END_MODULES_TABLE { 0, NULL, NULL, NULL } };

#define MODULE_ENTRY(id,acronym,descr,func) { (id), acronym, descr, func },

extern modules_table_t mod_table[];

extern size_t getNumberOfRegisteredModules(void);

/* Modules functions prototypes. */
extern void icmp  (const struct config_options const *, size_t *size);
extern void igmpv1(const struct config_options const *, size_t *size);
extern void igmpv3(const struct config_options const *, size_t *size);
extern void tcp   (const struct config_options const *, size_t *size);
extern void egp   (const struct config_options const *, size_t *size);
extern void udp   (const struct config_options const *, size_t *size);
extern void ripv1 (const struct config_options const *, size_t *size);
extern void ripv2 (const struct config_options const *, size_t *size);
extern void dccp  (const struct config_options const *, size_t *size);
extern void rsvp  (const struct config_options const *, size_t *size);
extern void ipsec (const struct config_options const *, size_t *size);
extern void eigrp (const struct config_options const *, size_t *size);
extern void ospf  (const struct config_options const *, size_t *size);
/* --- add yours here */

#endif
