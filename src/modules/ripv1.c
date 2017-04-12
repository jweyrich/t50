/* vim: set ts=2 et sw=2 : */
/** @file ripv1.c */
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

#define RIPVERSION 1

#include <assert.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <t50_defines.h>
#include <t50_config.h>
#include <t50_cksum.h>
#include <t50_memalloc.h>
#include <t50_modules.h>
#include <t50_randomizer.h>

/**
 * RIPv1 packet header configuration.
 *
 * This function configures and sends the RIPv1 packet header.
 *
 * @param co Pointer to T50 configuration structure.
 * @param size Pointer to packet size (updated by the function).
 */
void ripv1(const struct config_options *const __restrict__ co, size_t *size)
{
  size_t greoptlen,   /* GRE options size. */
         length;

  memptr_t buffer;

  struct iphdr *ip;
  struct iphdr *gre_ip;
  struct udphdr *udp;
  struct psdhdr *pseudo;

  assert(co != NULL);

  greoptlen = gre_opt_len(co);
  *size = sizeof(struct iphdr)  +
          sizeof(struct udphdr) +
          sizeof(struct psdhdr) +
          greoptlen             +
          rip_hdr_len(0);

  /* Try to reallocate packet, if necessary */
  alloc_packet(*size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, *size, co);

  /* GRE Encapsulation takes place. */
  gre_ip = gre_encapsulation(packet, co,
                             sizeof(struct iphdr)  +
                             sizeof(struct udphdr) +
                             rip_hdr_len(0));

  /* UDP Header structure making a pointer to IP Header structure. */
  udp         = (struct udphdr *)((unsigned char *)(ip + 1) + greoptlen);
  udp->source = udp->dest = htons(IPPORT_RIP);
  udp->len    = htons(sizeof(struct udphdr) + rip_hdr_len(0));
  udp->check  = 0;

  buffer.ptr = udp + 1;

  /*
   * Routing Information Protocol (RIP) (RFC 1058)
   *
   * 3.1 Message formats
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   | command (1)   | version (1)   |      must be zero (2)         |
   *   +---------------+---------------+-------------------------------+
   *   | address family identifier (2) |      must be zero (2)         |
   *   +-------------------------------+-------------------------------+
   *   |                         IP address (4)                        |
   *   +---------------------------------------------------------------+
   *   |                        must be zero (4)                       |
   *   +---------------------------------------------------------------+
   *   |                        must be zero (4)                       |
   *   +---------------------------------------------------------------+
   *   |                          metric (4)                           |
   *   +---------------------------------------------------------------+
   */
  *buffer.byte_ptr++ = co->rip.command;
  *buffer.byte_ptr++ = RIPVERSION;
  *buffer.word_ptr++ = FIELD_MUST_BE_ZERO;
  *buffer.word_ptr++ = htons(__RND(co->rip.family));
  *buffer.word_ptr++ = FIELD_MUST_BE_ZERO;
  *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->rip.address));
  *buffer.inaddr_ptr++ = FIELD_MUST_BE_ZERO;
  *buffer.inaddr_ptr++ = FIELD_MUST_BE_ZERO;
  *buffer.inaddr_ptr++ = htonl(__RND(co->rip.metric));

  /* PSEUDO Header structure making a pointer to Checksum. */
  pseudo = buffer.ptr;
  if (co->encapsulated)
  {
    pseudo->saddr = gre_ip->saddr;
    pseudo->daddr = gre_ip->daddr;
  }
  else
  {
    pseudo->saddr = ip->saddr;
    pseudo->daddr = ip->daddr;
  }
  pseudo->zero     = 0;
  pseudo->protocol = co->ip.protocol;
  pseudo->len      = htons(length = (buffer.ptr - (void *)udp));

  /* Computing the checksum. */
  udp->check  = co->bogus_csum ? RANDOM() :
                cksum(udp, (void *)(pseudo + 1) - (void *)udp);

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, co, *size);
}
