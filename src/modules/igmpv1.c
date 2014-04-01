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
int igmpv1(const socket_t fd, const struct config_options *co)
{
  size_t greoptlen,     /* GRE options size. */
         packet_size;

  /* Socket address, IP header and IGMPv1 header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* IGMPv1 header. */
  struct igmphdr * igmpv1;

  assert(o != NULL);

  /* GRE options size. */
  greoptlen = gre_opt_len(co->gre.options, co->encapsulated);

  /* Packet size. */
  packet_size = sizeof(struct iphdr) +
    greoptlen            +
    sizeof(struct igmphdr);

  /* Try to reallocate packet, if necessary */
  alloc_packet(packet_size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, packet_size, co);

  /* GRE Encapsulation takes place. */
  gre_encapsulation(packet, co,
        sizeof(struct iphdr) +
        sizeof(struct igmphdr));

  /* IGMPv1 Header structure making a pointer to Packet. */
  igmpv1        = (struct igmphdr *)((void *)ip + sizeof(struct iphdr) + greoptlen);
  igmpv1->type  = co->igmp.type;
  igmpv1->code  = co->igmp.code;
  igmpv1->group = INADDR_RND(co->igmp.group);
  igmpv1->csum  = 0;

  /* Computing the checksum. */
  igmpv1->csum  = co->bogus_csum ? random() : cksum(igmpv1, sizeof(struct igmphdr));

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, co, packet_size);

  /* Setting SOCKADDR structure. */
  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(IPPORT_RND(co->dest));
  sin.sin_addr.s_addr = co->ip.daddr;

  /* Sending packet. */
  if (sendto(fd, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
    return 1;

  return 0;
}
