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

#ifndef __COMMON_H
#define __COMMON_H

#define PACKAGE "T50"
#define SITE "http://github.com/merces/t50"

#if !(linux) || !(__linux__)
# error "Sorry! The T50 was only tested under Linux!"
#endif  /* __linux__ */

#define _GNU_SOURCE

#include <assert.h> /* for debugging purposes only */
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* This code prefers to use Linux headers rather than BSD favored */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/igmp.h>
#include <linux/dccp.h>
#include <linux/if_ether.h>

/* Purpose-built config library to be used by T50 modules */
#include <config.h>

#include <help.h>

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

/* NOTE: This will do nothing. Used only to prevent warnings. */
#define UNUSED_PARAM(x) { (x) = (x); }

/* NOTE: Macro used to test bitmasks */
#define TEST_BITS(x,bits) ((x) & (bits))

/* NOTE: Used to set/reset individual bits */
#define TRUE  1
#define FALSE 0
#define ON    1
#define OFF   0

/* Data types */
typedef uint32_t in_addr_t;
typedef int socket_t;

/* NOTE: This is HERE just to not redefine socket_t! */
#include <modules.h>

/* This will ease the buffers pointers manipulations. */
typedef union {
  void    *ptr;
  uint8_t *byte_ptr;
  uint16_t *word_ptr;
  uint32_t *dword_ptr;
  in_addr_t *inaddr_ptr;
  uint64_t *qword_ptr;
} mptr_t;

/* Limits */

/* #define RAND_MAX 2147483647 */ /* NOTE: Already defined @ stdlib.h */
#define CIDR_MINIMUM 8
#define CIDR_MAXIMUM 30

/* 24 bits?! */
#define MAXIMUM_IP_ADDRESSES  16777215

/* #define INADDR_ANY 0 */ /* NOTE: Already defined @ linux/in.h */
#define IPPORT_ANY 0

/* Global common protocol definitions used by code */
#define AUTH_TYPE_HMACNUL 0x0000
#define AUTH_TYPE_HMACMD5 0x0002
#define AUTH_TLEN_HMACMD5 16
#define AUTH_TLEN_HMACMD5 16
#define auth_hmac_md5_len(foo) ((foo) ? AUTH_TLEN_HMACMD5 : 0)

/* #define IPVERSION 4 */ /* NOTE: Already defined in netinet/in.h. */

/* NOTE: Both IP_MF & IP_DF are defined in netinet/ip.h. 
         But, since we are using linux/ip.h, they are needed here. */
#define IP_MF 0x2000
#define IP_DF 0x4000

/* T50 DEFINITIONS. */
#define IPPROTO_T50 69
#define FIELD_MUST_BE_NULL NULL
#define FIELD_MUST_BE_ZERO 0

/* Common protocol structures used by code */
/*
 * User Datagram Protocol (RFC 768)
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
 *                   0      7 8     15 16    23 24    31
 *                  +--------+--------+--------+--------+
 *                  |          source address           |
 *                  +--------+--------+--------+--------+
 *                  |        destination address        |
 *                  +--------+--------+--------+--------+
 *                  |  zero  |protocol|   UDP length    |
 *                  +--------+--------+--------+--------+
 *
 * If the computed  checksum  is zero,  it is transmitted  as all ones (the
 * equivalent  in one's complement  arithmetic).   An all zero  transmitted
 * checksum  value means that the transmitter  generated  no checksum  (for
 * debugging or for higher level protocols that don't care).
 */
struct psdhdr
{
  in_addr_t saddr;                  /* source address              */
  in_addr_t daddr;                  /* destination address         */
  uint8_t   zero;                   /* must be zero                */
  uint8_t   protocol;               /* protocol                    */
  uint16_t  len;                    /* header length               */
};

/* Randomizer macros and function */
#define __RND(foo) (((foo) == 0) ? random() : (foo))
#define INADDR_RND(foo) __RND((foo))
#define IPPORT_RND(foo) __RND((foo))

extern uint32_t NETMASK_RND(uint32_t);

/* ERROR macro */
#ifdef __HAVE_DEBUG__
#define ERROR(s) fprintf(stderr, "%s: %s at %s, line %d\n", PACKAGE, s, __FILE__, __LINE__);
#else
#define ERROR(s) fprintf(stderr, "%s: %s\n", PACKAGE, s);
#endif

/* The packet buffer. Reallocated as needed! */
extern uint8_t *packet;
extern size_t current_packet_size; /* available if necessary! updated by alloc_packet(). */

/* Realloc packet as needed. Used on module functions. */
extern void alloc_packet(size_t);

/* Common routines used by code */
int getNumberOfRegisteredModules(void);
extern struct cidr *config_cidr(uint32_t, in_addr_t);
/* Command line interface options validation. */
extern int checkConfigOptions(const struct config_options *);
/* Checksum calculation. */
extern uint16_t cksum(void *, size_t);
/* Command line interface options configuration. */
extern struct config_options *getConfigOptions(int, char **);
/* IP address and name resolve. */
extern in_addr_t resolv(char *);
/* Socket configuration. */
extern socket_t createSocket(void);
/* Show version info */
extern void show_version(void);
/* Help and usage message. */
extern void usage(void);

/* Common module routines used by code */
/* Function Name: ICMP packet header configuration. */
extern int icmp   (const socket_t, const struct config_options *);
/* Function Name: IGMPv1 packet header configuration. */
extern int igmpv1 (const socket_t, const struct config_options *);
/* Function Name: IGMPv3 packet header configuration. */
extern int igmpv3 (const socket_t, const struct config_options *);
/* Function Name: TCP packet header configuration. */
extern int tcp    (const socket_t, const struct config_options *);
/* Function Name: EGP packet header configuration. */
extern int egp    (const socket_t, const struct config_options *);
/* Function Name: UDP packet header configuration. */
extern int udp    (const socket_t, const struct config_options *);
/* Function Name: RIPv1 packet header configuration. */
extern int ripv1  (const socket_t, const struct config_options *);
/* Function Name: RIPv2 packet header configuration. */
extern int ripv2  (const socket_t, const struct config_options *);
/* Function Name: DCCP packet header configuration. */
extern int dccp   (const socket_t, const struct config_options *);
/* Function Name: RSVP packet header configuration. */
extern int rsvp   (const socket_t, const struct config_options *);
/* Function Name: IPSec packet header configuration. */
extern int ipsec  (const socket_t, const struct config_options *);
/* Function Name: EIGRP packet header configuration. */
extern int eigrp  (const socket_t, const struct config_options *);
/* Function Name: OSPF packet header configuration. */
extern int ospf   (const socket_t, const struct config_options *);

#endif /* __COMMON_H */
