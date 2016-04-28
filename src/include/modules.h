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

#ifndef __MODULES_INCLUDED__
#define __MODULES_INCLUDED__

#include <stddef.h>

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

/** 
 * Modules entry structure.
 *
 * Used for modules definitions. And table iterators.
 */
typedef struct
{
  int protocol_id;
  char *acronym;
  char *description;
  module_func_ptr_t func;
  int *valid_options;
} modules_table_t;

#define BEGIN_MODULES_TABLE modules_table_t mod_table[] = {
#define END_MODULES_TABLE { 0, NULL, NULL, NULL, NULL } };
#define MODULE_ENTRY(id,acronym,descr,func) { (id), acronym, descr, func, func ## _validopts },

#define VALID_OPTIONS_TABLE(func, ...) static int func ## _validopts[] = { __VA_ARGS__, 0 };

/**
 * The modules table is global through all the code.
 */
extern modules_table_t mod_table[];

extern size_t  get_number_of_registered_modules(void);
extern int    *get_module_valid_options_list(int);

/* Modules functions prototypes. */
extern void icmp  (const struct config_options *const __restrict__, size_t *size);
extern void igmpv1(const struct config_options *const __restrict__, size_t *size);
extern void igmpv3(const struct config_options *const __restrict__, size_t *size);
extern void tcp   (const struct config_options *const __restrict__, size_t *size);
extern void egp   (const struct config_options *const __restrict__, size_t *size);
extern void udp   (const struct config_options *const __restrict__, size_t *size);
extern void ripv1 (const struct config_options *const __restrict__, size_t *size);
extern void ripv2 (const struct config_options *const __restrict__, size_t *size);
extern void dccp  (const struct config_options *const __restrict__, size_t *size);
extern void rsvp  (const struct config_options *const __restrict__, size_t *size);
extern void ipsec (const struct config_options *const __restrict__, size_t *size);
extern void eigrp (const struct config_options *const __restrict__, size_t *size);
extern void ospf  (const struct config_options *const __restrict__, size_t *size);
/* --- add yours here */

#endif
