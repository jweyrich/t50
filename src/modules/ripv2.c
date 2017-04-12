/* vim: set ts=2 et sw=2 : */
/** @file ripv2.c */
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

#define RIPVERSION 2

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
 * RIPv2 packet header configuration.
 *
 * This function configures and sends the RIPv2 packet header.
 *
 * @param co Pointer to T50 configuration structure.
 * @param size Pointer to packet size (updated by the function).
 */
void ripv2(const struct config_options *const __restrict__ co, size_t *size)
{
  size_t greoptlen,     /* GRE options size. */
         length,
         counter;

  memptr_t buffer;

  struct iphdr  *ip;
  struct iphdr  *gre_ip;
  struct udphdr *udp;
  struct psdhdr *pseudo;

  assert(co != NULL);

  greoptlen = gre_opt_len(co);
  *size = sizeof(struct iphdr)  +
          sizeof(struct udphdr) +
          sizeof(struct psdhdr) +
          greoptlen             +
          rip_hdr_len(co->rip.auth);

  /* Try to reallocate packet, if necessary */
  alloc_packet(*size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, *size, co);

  /* GRE Encapsulation takes place. */
  gre_ip = gre_encapsulation(packet, co,
                             sizeof(struct iphdr)  +
                             sizeof(struct udphdr) +
                             rip_hdr_len(co->rip.auth));

  /* UDP Header structure making a pointer to  IP Header structure. */
  udp         = (struct udphdr *)((unsigned char *)(ip + 1) + greoptlen);
  udp->source = udp->dest = htons(IPPORT_RIP);
  udp->len    = htons(sizeof(struct udphdr) +
                      rip_hdr_len(co->rip.auth));
  udp->check  = 0;

  buffer.ptr = udp + 1;

  /*
   * RIP Version 2 -- Carrying Additional Information (RFC 1388)
   *
   * 3. Protocol Extensions
   *
   * The new RIP datagram format is:
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   | Command (1)   | Version (1)   |       Routing Domain (2)      |
   *   +---------------+---------------+-------------------------------+
   *   | Address Family Identifier (2) |       Route Tag (2)           |
   *   +-------------------------------+-------------------------------+
   *   |                         IP Address (4)                        |
   *   +---------------------------------------------------------------+
   *   |                         Subnet Mask (4)                       |
   *   +---------------------------------------------------------------+
   *   |                         Next Hop (4)                          |
   *   +---------------------------------------------------------------+
   *   |                         Metric (4)                            |
   *   +---------------------------------------------------------------+
   *
   * XXX Playing with:
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   | Command (1)   | Version (1)   |       Routing Domain (2)      |
   *   +---------------+---------------+-------------------------------+
   */
  *buffer.byte_ptr++ = co->rip.command;
  *buffer.byte_ptr++ = RIPVERSION;
  *buffer.word_ptr++ = htons(__RND(co->rip.domain));

  /* DON'T NEED THIS */
  /* length = sizeof(struct udphdr) + RIP_HEADER_LENGTH; */

  /*
   * RIP-2 MD5 Authentication (RFC 2082)
   *
   * 3.2.  Processing Algorithm
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |             0xFFFF            |    Authentication Type (2)    |
   *   +-------------------------------+-------------------------------+
   *   |    RIP-2 Packet Length        |    Key ID    | Auth Data Len  |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |               Sequence Number (non-decreasing)                |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |               reserved must be zero                           |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |               reserved must be zero                           |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |                                                               |
   *   /    (RIP-2 Packet Length - 24) bytes of Data                   /
   *   |                                                               |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |             0xFFFF            |       0x01                    |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   /  Authentication Data (var. length; 16 bytes with Keyed MD5)   /
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *
   * XXX Playing with:
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |             0xFFFF            |    Authentication Type (2)    |
   *   +-------------------------------+-------------------------------+
   *   |    RIP-2 Packet Length        |    Key ID    | Auth Data Len  |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |               Sequence Number (non-decreasing)                |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |               reserved must be zero                           |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |               reserved must be zero                           |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  if (co->rip.auth)
  {
    *buffer.word_ptr++ = 0xffff;
    *buffer.word_ptr++ = htons(3);
    *buffer.word_ptr++ = htons(RIP_HEADER_LENGTH + RIP_AUTH_LENGTH + RIP_MESSAGE_LENGTH);
    *buffer.byte_ptr++ = co->rip.key_id;
    *buffer.byte_ptr++ = RIP_AUTH_LENGTH;
    *buffer.dword_ptr++ = htonl(__RND(co->rip.sequence));
    *buffer.dword_ptr++ = FIELD_MUST_BE_ZERO;
    *buffer.dword_ptr++ = FIELD_MUST_BE_ZERO;
  }

  /*
   * XXX Playing with:
   *
   * RIP Version 2 -- Carrying Additional Information (RFC 1388)
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   | Address Family Identifier (2) |       Route Tag (2)           |
   *   +-------------------------------+-------------------------------+
   *   |                         IP Address (4)                        |
   *   +---------------------------------------------------------------+
   *   |                         Subnet Mask (4)                       |
   *   +---------------------------------------------------------------+
   *   |                         Next Hop (4)                          |
   *   +---------------------------------------------------------------+
   *   |                         Metric (4)                            |
   *   +---------------------------------------------------------------+
   *
   * RIP-2 MD5 Authentication (RFC 2082)
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |                                                               |
   *   /    (RIP-2 Packet Length - 24) bytes of Data                   /
   *   |                                                               |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  *buffer.word_ptr++ = htons(__RND(co->rip.family));
  *buffer.word_ptr++ = htons(__RND(co->rip.tag));
  *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->rip.address));
  *buffer.inaddr_ptr++ = NETMASK_RND(htonl(co->rip.netmask));
  *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->rip.next_hop));
  *buffer.inaddr_ptr++ = htonl(__RND(co->rip.metric));

  /*
   * XXX Playing with:
   *
   * RIP-2 MD5 Authentication (RFC 2082)
   *
   *    0                   1                   2                   3 3
   *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   |             0xFFFF            |       0x01                    |
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *   /  Authentication Data (var. length; 16 bytes with Keyed MD5)   /
   *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  if (co->rip.auth)
  {
    size_t size;

    *buffer.word_ptr++ = 0xffff;
    *buffer.word_ptr++ = htons(1);

    /*
     * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
     */
    size = auth_hmac_md5_len(co->rip.auth);
    /* NOTE: Assume size > 0. */
    for (counter = 0; likely(counter < size); counter++)
      *buffer.byte_ptr++ = RANDOM();
  }

  /* PSEUDO Header structure making a pointer to Checksum. */
  pseudo           = buffer.ptr;
  if (co->encapsulated)
  {
    pseudo->saddr    = gre_ip->saddr;
    pseudo->daddr    = gre_ip->daddr;
  }
  else
  {
    pseudo->saddr    = ip->saddr;
    pseudo->daddr    = ip->daddr;
  }
  pseudo->zero     = 0;
  pseudo->protocol = co->ip.protocol;
  pseudo->len      = htons(length = (buffer.ptr - (void *)udp));

  /* FIX: buffer.ptr points to 'pseudo' So, it is simple to calculate the size used
          by cksum() function.

          This is easier than accumulate the "length" through
          various conditionals above! */

  /* Computing the checksum. */
  udp->check  = co->bogus_csum ? RANDOM() :
                cksum(udp, (void *)(pseudo + 1) - (void *)udp);

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, co, *size);
}
