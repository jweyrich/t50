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

#include <common.h>

/* Function Name: UDP packet header configuration.

Description:   This function configures and sends the UDP packet header.

Targets:       N/A */
int udp(const socket_t fd, const struct config_options *o)
{
  /* GRE options size. */
  size_t greoptlen = gre_opt_len(o->gre.options, o->encapsulated);

  /* Packet size. */
  const uint32_t packet_size = sizeof(struct iphdr)  + 
    greoptlen             + 
    sizeof(struct udphdr);

  /* Checksum offset and GRE offset. */
  uint32_t offset;

  /* Packet and Checksum. */
  uint8_t *checksum;

  /* Socket address, IP header, UDP header and PSEUDO header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr * gre_ip;

  /* UDP header and PSEUDO header. */
  struct udphdr * udp;
  struct psdhdr * pseudo;

  /* Setting SOCKADDR structure. */
  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(IPPORT_RND(o->dest));
  sin.sin_addr.s_addr = o->ip.daddr;

  /* Try to reallocate packet, if necessary */
  alloc_packet(packet_size);

  /* IP Header structure making a pointer to Packet. */
  ip           = ip_header(packet, packet_size, o);

  /* Computing the GRE Offset. */
  offset = sizeof(struct iphdr);

  gre_ip = gre_encapsulation(packet, o,
   sizeof(struct iphdr) + sizeof(struct udphdr));

  /* UDP Header structure making a pointer to  IP Header structure. */
  udp         = (struct udphdr *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
  udp->source = htons(IPPORT_RND(o->source)); 
  udp->dest   = htons(IPPORT_RND(o->dest));
  udp->len    = htons(sizeof(struct udphdr));
  udp->check  = 0;
  /* Computing the Checksum offset. */
  offset = sizeof(struct udphdr);

  /* Storing both Checksum and Packet. */
  checksum = (uint8_t *) udp + offset;

  /* PSEUDO Header structure making a pointer to Checksum. */
  pseudo           = (struct psdhdr *)(checksum + (offset - sizeof(struct udphdr)));
  pseudo->saddr    = o->encapsulated ? gre_ip->saddr : ip->saddr;
  pseudo->daddr    = o->encapsulated ? gre_ip->daddr : ip->daddr;
  pseudo->zero     = 0;
  pseudo->protocol = o->ip.protocol;
  pseudo->len      = htons(offset);
  /* Computing the Checksum offset. */
  offset  += sizeof(struct psdhdr);

  /* Computing the checksum. */
  udp->check  = o->bogus_csum ? 
    __16BIT_RND(0) : 
    cksum((uint16_t *)udp, offset);

  gre_checksum(packet, o, packet_size);

  /* Sending packet. */
  if (sendto(fd, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
    return 1;

  return 0;
}
