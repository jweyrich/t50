/* vim: set ts=2 et sw=2 : */
/** @file udp.c */
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

#include <assert.h>
#include <linux/udp.h>
#include <t50_config.h>
#include <t50_cksum.h>
#include <t50_memalloc.h>
#include <t50_modules.h>
#include <t50_randomizer.h>

/**
 * UDP packet header configuration.
 *
 * Configures the UDP packet header.
 * A pointer to this function will be on modules table.
 *
 * @param co Pointer to T50 configuration structure.
 * @param size Pointer to packet size (updated by the function).
 */
void udp(const struct config_options *const __restrict__ co, size_t *size)
{
  size_t greoptlen;   /* GRE options size. */

  struct iphdr *ip;
  struct iphdr *gre_ip;
  struct udphdr *udp;
  struct psdhdr *pseudo;

  assert(co != NULL);

  greoptlen = gre_opt_len(co);
  *size = sizeof(struct iphdr)  +
          sizeof(struct udphdr) +
          sizeof(struct psdhdr) +
          greoptlen;

  /* Try to reallocate packet, if necessary */
  alloc_packet(*size);

  /* Fill IP header. */
  ip = ip_header(packet, *size, co);

  gre_ip = gre_encapsulation(packet, co,
                             sizeof(struct iphdr) +
                             sizeof(struct udphdr));

  /* UDP Header structure making a pointer to  IP Header structure. */
  udp         = (struct udphdr *)((unsigned char *)(ip + 1) + greoptlen);
  udp->source = htons(IPPORT_RND(co->source));
  udp->dest   = htons(IPPORT_RND(co->dest));
  udp->len    = htons(sizeof(struct udphdr));
  udp->check  = 0;    /* needed 'cause of cksum(), below! */

  /* Fill PSEUDO Header structure. */
  pseudo      = (struct psdhdr *)(udp + 1);

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
  pseudo->len      = htons(sizeof(struct udphdr));

  /* Computing the checksum. */
  udp->check  = co->bogus_csum ? RANDOM() :
                cksum(udp, (void *)(pseudo + 1) - (void *)udp);

  gre_checksum(packet, co, *size);
}
