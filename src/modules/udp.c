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
void udp(const struct config_options * const __restrict__ co, size_t *size)
{
  size_t greoptlen;   /* GRE options size. */

  struct iphdr *ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr *gre_ip;

  /* UDP header and PSEUDO header. */
  struct udphdr *udp;
  struct psdhdr *pseudo;

  assert(o != NULL);

  greoptlen = gre_opt_len(co->gre.options, co->encapsulated);
  *size = sizeof(struct iphdr) + greoptlen + sizeof(struct udphdr);

  /* Try to reallocate packet, if necessary */
  alloc_packet(*size);

  /* Fill IP header. */
  ip = ip_header(packet, *size, co);

  gre_ip = gre_encapsulation(packet, co,
    sizeof(struct iphdr) + sizeof(struct udphdr));

  /* UDP Header structure making a pointer to  IP Header structure. */
  udp         = (struct udphdr *)((void *)ip + sizeof(struct iphdr) + greoptlen);
  udp->source = htons(IPPORT_RND(co->source));
  udp->dest   = htons(IPPORT_RND(co->dest));
  udp->len    = htons(sizeof(struct udphdr));
  udp->check  = 0;

  /* Fill PSEUDO Header structure. */
  pseudo           = (struct psdhdr *)((void *)udp + sizeof(struct udphdr));
  pseudo->saddr    = co->encapsulated ? gre_ip->saddr : ip->saddr;
  pseudo->daddr    = co->encapsulated ? gre_ip->daddr : ip->daddr;
  pseudo->zero     = 0;
  pseudo->protocol = co->ip.protocol;
  pseudo->len      = htons(sizeof(struct udphdr));

  /* Computing the checksum. */
  udp->check  = co->bogus_csum ? random() :
    cksum(udp, sizeof(struct udphdr) + sizeof(struct psdhdr));

  gre_checksum(packet, co, *size);
}
