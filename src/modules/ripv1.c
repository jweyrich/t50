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

#define RIPVERSION 1

#include <common.h>

/* Function Name: RIPv1 packet header configuration.

Description:   This function configures and sends the RIPv1 packet header.

Targets:       N/A */
void ripv1(const struct config_options *const co, size_t *size)
{
  size_t greoptlen,   /* GRE options size. */
         length;

  mptr_t buffer;

  struct iphdr * ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr * gre_ip;

  /* UDP header and PSEUDO header. */
  struct udphdr * udp;
  struct psdhdr * pseudo;

  assert(co != NULL);

  greoptlen = gre_opt_len(co);
  *size = sizeof(struct iphdr)  +
          greoptlen             +
          sizeof(struct udphdr) +
          rip_hdr_len(0)        +
          sizeof(struct psdhdr);

  /* Try to reallocate packet, if necessary */
  alloc_packet(*size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, *size, co);

  /* GRE Encapsulation takes place. */
  gre_ip = gre_encapsulation(packet, co,
        sizeof(struct iphdr) +
        sizeof(struct udphdr)      +
        rip_hdr_len(0));

  /* UDP Header structure making a pointer to IP Header structure. */
  udp         = (struct udphdr *)((void *)(ip + 1) + greoptlen);
  udp->source = htons(IPPORT_RIP);
  udp->dest   = htons(IPPORT_RIP);
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
  *buffer.inaddr_ptr++ = INADDR_RND(co->rip.address);
  *buffer.inaddr_ptr++ = FIELD_MUST_BE_ZERO;
  *buffer.inaddr_ptr++ = FIELD_MUST_BE_ZERO;
  *buffer.inaddr_ptr++ = htonl(__RND(co->rip.metric));

  /* DON'T NEED THIS */
  /* length += RIP_HEADER_LENGTH + RIP_MESSAGE_LENGTH; */

  /* PSEUDO Header structure making a pointer to Checksum. */
  pseudo           = buffer.ptr;
  pseudo->saddr    = co->encapsulated ? gre_ip->saddr : ip->saddr;
  pseudo->daddr    = co->encapsulated ? gre_ip->daddr : ip->daddr;
  pseudo->zero     = 0;
  pseudo->protocol = co->ip.protocol;
  pseudo->len      = htons(length = (buffer.ptr - (void *)udp));

  /* Computing the checksum. */
  udp->check  = co->bogus_csum ? RANDOM() : 
    cksum(udp, (size_t)((void *)(pseudo + 1) - (void *)udp));

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, co, *size);
}
