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

/* Function Name: IGMPv1 packet header configuration.
Description:   This function configures and sends the IGMPv1 packet header. */
int igmpv1(const socket_t fd, const struct config_options *o)
{
  /* GRE options size. */
  size_t greoptlen = gre_opt_len(o->gre.options, o->encapsulated);

  /* Packet size. */
  const uint32_t packet_size = sizeof(struct iphdr) + 
    greoptlen            + 
    sizeof(struct igmphdr);

  /* Checksum offset and GRE offset. */
  uint32_t offset;

  /* Socket address, IP header and IGMPv1 header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* IGMPv1 header. */
  struct igmphdr * igmpv1;

  /* Setting SOCKADDR structure. */
  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(IPPORT_RND(o->dest));
  sin.sin_addr.s_addr = o->ip.daddr;

  /* Try to reallocate packet, if necessary */
  alloc_packet(packet_size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, packet_size, o);

  /* Computing the GRE Offset. */
  offset = sizeof(struct iphdr);

  /* GRE Encapsulation takes place. */
  gre_encapsulation(packet, o,
        sizeof(struct iphdr) + 
        sizeof(struct igmphdr));

  /* IGMPv1 Header structure making a pointer to Packet. */
  igmpv1        = (struct igmphdr *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
  igmpv1->type  = o->igmp.type;
  igmpv1->code  = o->igmp.code;
  igmpv1->group = INADDR_RND(o->igmp.group);
  igmpv1->csum  = 0;
  /* Computing the Packet offset. */
  offset = sizeof(struct igmphdr);

  /* Computing the checksum. */
  igmpv1->csum  = o->bogus_csum ? 
    __16BIT_RND(0) : 
    cksum((uint16_t *)igmpv1, offset);

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, o, packet_size);

  /* Sending packet. */
  if (sendto(fd, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
    return 1;

  return 0;
}
