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
#include <netinet/in.h>
#include <t50_typedefs.h>
#include <t50_config.h>

/* Purpose-built protocol libraries to be used by T50 modules */
#include <protocol/t50_ip.h>
#include <protocol/t50_egp.h>
#include <protocol/t50_gre.h>
#include <protocol/t50_rip.h>
#include <protocol/t50_igmp.h>
#include <protocol/t50_ospf.h>
#include <protocol/t50_rsvp.h>
#include <protocol/t50_eigrp.h>
#include <protocol/t50_tcp_options.h>
/* NOTE: Insert your new protocol header here and change the modules table @ modules.c. */

/**
 * User Datagram Protocol (RFC 768) Pseudo Header structure.
 *
 * Checksum is the 16-bit one's complement of the one's complement sum of a
 * pseudo header of information from the IP header, the UDP header, and the
 * data,  padded  with zero octets  at the end (if  necessary)  to  make  a
 * multiple of two octets.
 *
 * The pseudo  header  conceptually prefixed to the UDP header contains the
 * source  address,  the destination  address,  the protocol,  and the  UDP
 * length.   This information gives protection against misrouted datagrams.
 * This checksum procedure is the same as is used in TCP.
 *
 *      0      7 8     15 16    23 24    31
 *     +--------+--------+--------+--------+
 *     |          source address           |
 *     +--------+--------+--------+--------+
 *     |        destination address        |
 *     +--------+--------+--------+--------+
 *     |  zero  |protocol|   UDP length    |
 *     +--------+--------+--------+--------+
 *
 * If the computed  checksum  is zero,  it is transmitted  as all ones (the
 * equivalent  in one's complement  arithmetic).   An all zero  transmitted
 * checksum  value means that the transmitter  generated  no checksum  (for
 * debugging or for higher level protocols that don't care).
 */
struct psdhdr
{
  in_addr_t saddr;      /* source address      */
  in_addr_t daddr;      /* destination address */
  uint8_t   zero;       /* must be zero        */
  uint8_t   protocol;   /* protocol            */
  uint16_t  len;        /* header length       */
};

typedef void (*module_func_ptr_t)(const struct config_options *const __restrict__, size_t *);

/**
 * Modules entry structure.
 *
 * Used for modules definitions. And table iterators.
 */
typedef struct
{
  int protocol_id;
  char *name;
  char *description;
  module_func_ptr_t func;
  int *valid_options;
} modules_table_t;

/* Macros used to define the modules table. */
#define BEGIN_MODULES_TABLE modules_table_t mod_table[] = {
#define END_MODULES_TABLE { 0, NULL, NULL, NULL, NULL } };
#define MODULE_ENTRY(id,name,descr,func) { (id), name, descr, func, func ## _validopts },

#define VALID_OPTIONS_TABLE(func, ...) static int func ## _validopts[] = { __VA_ARGS__, 0 };

/**
 * The modules table is global through all the code.
 */
extern modules_table_t mod_table[]; // Must be extern here!
extern const uint32_t number_of_modules;
extern uint32_t indices[];

int    *get_module_valid_options_list(int);
void    build_indices(void);
uint32_t get_index(struct config_options *);

/* Modules functions prototypes. */
void icmp  (const struct config_options *const __restrict__, size_t *);
void igmpv1(const struct config_options *const __restrict__, size_t *);
void igmpv3(const struct config_options *const __restrict__, size_t *);
void tcp   (const struct config_options *const __restrict__, size_t *);
void egp   (const struct config_options *const __restrict__, size_t *);
void udp   (const struct config_options *const __restrict__, size_t *);
void ripv1 (const struct config_options *const __restrict__, size_t *);
void ripv2 (const struct config_options *const __restrict__, size_t *);
void dccp  (const struct config_options *const __restrict__, size_t *);
void rsvp  (const struct config_options *const __restrict__, size_t *);
void ipsec (const struct config_options *const __restrict__, size_t *);
void eigrp (const struct config_options *const __restrict__, size_t *);
void ospf  (const struct config_options *const __restrict__, size_t *);
/* --- add yours here */

#endif
