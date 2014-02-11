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

#define RIPVERSION 2

#include <common.h>

/* Function Name: RIPv2 packet header configuration.

Description:   This function configures and sends the RIPv2 packet header.

Targets:       N/A */
int ripv2(const socket_t fd, const struct config_options *o)
{
  size_t greoptlen,     /* GRE options size. */
         packet_size,
         offset,
         counter;

  /* Packet and Checksum. */
  mptr_t buffer;

  /* Socket address, IP header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr * gre_ip;

  /* UDP header and PSEUDO header. */
  struct udphdr * udp;
  struct psdhdr * pseudo;

  greoptlen = gre_opt_len(o->gre.options, o->encapsulated);
  packet_size = sizeof(struct iphdr)  + 
    greoptlen             + 
    sizeof(struct udphdr) + 
    rip_hdr_len(o->rip.auth);

  /* Try to reallocate packet, if necessary */
  alloc_packet(packet_size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, packet_size, o);

  /* GRE Encapsulation takes place. */
  gre_ip = gre_encapsulation(packet, o,
        sizeof(struct iphdr) + 
        sizeof(struct udphdr) + 
        rip_hdr_len(o->rip.auth));

  /* UDP Header structure making a pointer to  IP Header structure. */
  udp         = (struct udphdr *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
  udp->source = htons(IPPORT_RIP); 
  udp->dest   = htons(IPPORT_RIP);
  udp->len    = htons(sizeof(struct udphdr) + 
      rip_hdr_len(o->rip.auth));
  udp->check  = 0;
  /* Computing the Checksum offset. */
  offset = sizeof(struct udphdr);

  /* Storing both Checksum and Packet. */
  buffer.ptr = (void *)udp + offset;

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
  *buffer.byte_ptr++ = o->rip.command;
  *buffer.byte_ptr++ = RIPVERSION;
  *buffer.word_ptr++ = htons(__16BIT_RND(o->rip.domain));
  /* Computing the Checksum offset. */
  offset += RIP_HEADER_LENGTH;	
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
  if (o->rip.auth)
  {
    *buffer.word_ptr++ = htons(0xffff);
    *buffer.word_ptr++ = htons(0x0003);
    *buffer.word_ptr++ = htons(RIP_HEADER_LENGTH + 
        RIP_AUTH_LENGTH         + 
        RIP_MESSAGE_LENGTH);
    *buffer.byte_ptr++ = o->rip.key_id;
    *buffer.byte_ptr++ = RIP_AUTH_LENGTH;
    *buffer.dword_ptr++ = htonl(__32BIT_RND(o->rip.sequence));
    *buffer.dword_ptr++ = FIELD_MUST_BE_ZERO;
    *buffer.dword_ptr++ = FIELD_MUST_BE_ZERO;
    /* Computing the Checksum offset. */
    offset += RIP_AUTH_LENGTH;
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
  *buffer.word_ptr++ = htons(__16BIT_RND(o->rip.family));
  *buffer.word_ptr++ = htons(__16BIT_RND(o->rip.tag));
  *buffer.inaddr_ptr++ = INADDR_RND(o->rip.address);
  *buffer.inaddr_ptr++ = NETMASK_RND(htonl(o->rip.netmask));
  *buffer.inaddr_ptr++ = INADDR_RND(o->rip.next_hop);
  *buffer.inaddr_ptr++ = htonl(__32BIT_RND(o->rip.metric));
  /* Computing the Checksum offset. */
  offset += RIP_MESSAGE_LENGTH;
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
  if (o->rip.auth)
  {
    *buffer.word_ptr++ = htons(0xffff);
    *buffer.word_ptr++ = htons(0x0001);
    /*
     * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
     */
    for(counter = 0 ; counter < auth_hmac_md5_len(o->rip.auth) ; counter++)
      *buffer.byte_ptr++ = __8BIT_RND(0);

    /* Computing the Checksum offset. */
    offset += RIP_TRAILER_LENGTH + auth_hmac_md5_len(o->rip.auth);
  }

  /* PSEUDO Header structure making a pointer to Checksum. */
  pseudo           = (struct psdhdr *)buffer.ptr;
  pseudo->saddr    = o->encapsulated ? gre_ip->saddr : ip->saddr;
  pseudo->daddr    = o->encapsulated ? gre_ip->daddr : ip->daddr;
  pseudo->zero     = 0;
  pseudo->protocol = o->ip.protocol;
  pseudo->len      = htons(offset);
  /* Computing the Checksum offset. */
  offset += sizeof(struct psdhdr);

  /* Computing the checksum. */
  udp->check  = o->bogus_csum ? 
    __16BIT_RND(0) : 
    cksum(udp, offset);

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, o, packet_size);

  /* Setting SOCKADDR structure. */
  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(IPPORT_RND(o->dest));
  sin.sin_addr.s_addr = o->ip.daddr;

  /* Sending packet. */
  if (sendto(fd, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
    return 1;

  return 0;
}
