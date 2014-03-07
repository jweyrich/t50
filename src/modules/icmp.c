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

/* Function Name: ICMP packet header configuration.

Description:   This function configures and sends the ICMP packet header.

Targets:       N/A */
int icmp(const socket_t fd, const struct config_options *o)
{
  size_t greoptlen,   /* GRE options size. */
         packet_size,
         offset;

  /* Socket address and IP header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* ICMP header. */
  struct icmphdr * icmp;

  assert(o != NULL);

  greoptlen = gre_opt_len(o->gre.options, o->encapsulated);
  packet_size = sizeof(struct iphdr) +
                greoptlen            +
                sizeof(struct icmphdr);

  /* Try to reallocate packet, if necessary */
  alloc_packet(packet_size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, packet_size, o);

  /* GRE Encapsulation takes place. */
  gre_encapsulation(packet, o,
        sizeof(struct iphdr) +
        sizeof(struct icmphdr));

  /* ICMP Header structure making a pointer to Packet. */
  icmp                   = (struct icmphdr *)((void *)ip + sizeof(struct iphdr) + greoptlen);
  icmp->type             = o->icmp.type;
  icmp->code             = o->icmp.code;
  icmp->un.echo.id       = htons(__RND(o->icmp.id));
  icmp->un.echo.sequence = htons(__RND(o->icmp.sequence));
  if (o->icmp.type == ICMP_REDIRECT   &&
      (o->icmp.code == ICMP_REDIR_HOST ||
       o->icmp.code == ICMP_REDIR_NET))
    icmp->un.gateway = INADDR_RND(o->icmp.gateway);
  icmp->checksum = 0;

  /* Computing the Packet offset. */
  offset = sizeof(struct icmphdr);

  /* Computing the checksum. */
  icmp->checksum = o->bogus_csum ? random() : cksum(icmp, offset);

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
