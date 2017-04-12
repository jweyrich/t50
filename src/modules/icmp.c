/* vim: set ts=2 et sw=2 : */
/** @file icmp.c */
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
#include <linux/ip.h>
#include <linux/icmp.h>
#include <t50_config.h>
#include <t50_cksum.h>
#include <t50_memalloc.h>
#include <t50_modules.h>
#include <t50_randomizer.h>

/**
 * ICMP packet header configuration.
 *
 * This function configures and sends the ICMP packet header.
 *
 * @param co Pointer to T50 configuration structure.
 * @param size Pointer to packet size (updated by the function).
 */
void icmp(const struct config_options *const __restrict__ co, size_t *size)
{
  size_t greoptlen;   /* GRE options size. */

  struct iphdr *ip;

  /* ICMP header. */
  struct icmphdr *icmp;

  assert(co != NULL);

  greoptlen = gre_opt_len(co);
  *size = sizeof(struct iphdr)   +
          sizeof(struct icmphdr) +
          greoptlen;

  /* Try to reallocate packet, if necessary */
  alloc_packet(*size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, *size, co);

  /* GRE Encapsulation takes place. */
  gre_encapsulation(packet, co,
                    sizeof(struct iphdr) +
                    sizeof(struct icmphdr));

  /* ICMP Header structure making a pointer to Packet. */
  icmp                   = (struct icmphdr *)((unsigned char *)(ip + 1) + greoptlen);
  icmp->type             = co->icmp.type;
  icmp->code             = co->icmp.code;
  icmp->un.echo.id       = htons(__RND(co->icmp.id));
  icmp->un.echo.sequence = htons(__RND(co->icmp.sequence));

  if (co->icmp.type == ICMP_REDIRECT)
    switch (co->icmp.code)
    {
    case ICMP_REDIR_HOST:
    case ICMP_REDIR_NET:
      icmp->un.gateway = htonl(INADDR_RND(co->icmp.gateway));
    }

  icmp->checksum = 0;

  /* Computing the checksum. */
  icmp->checksum = co->bogus_csum ? RANDOM() : cksum(icmp, sizeof(struct icmphdr));

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, co, *size);
}
