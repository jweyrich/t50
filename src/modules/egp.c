/* vim: set ts=2 et sw=2 : */
/** @file egp.c */
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
#include <t50_config.h>
#include <t50_cksum.h>
#include <t50_memalloc.h>
#include <t50_modules.h>
#include <t50_randomizer.h>

/**
 * EGP packet header configuration.
 *
 * This function configures and sends the EGP packet header.
 *
 * @param co Pointer to T50 configuration structure.
 * @param size Pointer to packet size (updated by the function).
 */
void egp(const struct config_options *const __restrict__ co, size_t *size)
{
  size_t greoptlen;   /* GRE options size. */

  struct iphdr *ip;

  /* EGP header and EGP acquire header. */
  struct egp_hdr *egp;
  struct egp_acq_hdr *egp_acq;

  assert(co != NULL);

  greoptlen = gre_opt_len(co);
  *size = sizeof(struct iphdr)       +
          sizeof(struct egp_hdr)     +
          sizeof(struct egp_acq_hdr) +
          greoptlen;

  /* Try to reallocate packet, if necessary */
  alloc_packet(*size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, *size, co);

  /* GRE Encapsulation takes place. */
  gre_encapsulation(packet, co,
                    sizeof(struct iphdr)    +
                    sizeof(struct egp_hdr)  +
                    sizeof(struct egp_acq_hdr));

  /*
   * @nbrito -- Tue Jan 18 11:09:34 BRST 2011
   * XXX Have to work a little bit more deeply in packet building.
   * XXX Checking EGP Type and building appropriate header.
   */
  /* EGP Header structure making a pointer to Packet. */
  egp           = (struct egp_hdr *)((unsigned char *)(ip + 1) + greoptlen);
  egp->version  = EGPVERSION;
  egp->type     = co->egp.type;
  egp->code     = co->egp.code;
  egp->status   = co->egp.status;
  egp->as       = __RND(co->egp.as);
  egp->sequence = __RND(co->egp.sequence);
  egp->check    = 0;

  /* EGP Acquire Header structure. */
  egp_acq        = (struct egp_acq_hdr *)(egp + 1);
  egp_acq->hello = __RND(co->egp.hello);
  egp_acq->poll  = __RND(co->egp.poll);

  /* Computing the checksum. */
  egp->check    = co->bogus_csum ? RANDOM() :
                  cksum(egp, (unsigned char *)(egp_acq + 1) - (unsigned char *)egp);

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, co, *size);
}
