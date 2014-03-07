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

/* Function Name: EGP packet header configuration.

Description:   This function configures and sends the EGP packet header.

Targets:       N/A */
int egp(const socket_t fd, const struct config_options *o)
{
  size_t greoptlen,   /* GRE options size. */
         packet_size,
         offset;

  /* Socket address and IP header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* EGP header and EGP acquire header. */
  struct egp_hdr * egp;
  struct egp_acq_hdr * egp_acq;

  assert(o != NULL);

  greoptlen = gre_opt_len(o->gre.options, o->encapsulated);
  packet_size = sizeof(struct iphdr)   +
    greoptlen              +
    sizeof(struct egp_hdr) +
    sizeof(struct egp_acq_hdr);

  /* Try to reallocate packet, if necessary */
  alloc_packet(packet_size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, packet_size, o);

  /* GRE Encapsulation takes place. */
  gre_encapsulation(packet, o,
        sizeof(struct iphdr) +
        sizeof(struct egp_hdr)     +
        sizeof(struct egp_acq_hdr));

  /*
   * @nbrito -- Tue Jan 18 11:09:34 BRST 2011
   * XXX Have to work a little bit more deeply in packet building.
   * XXX Checking EGP Type and building appropriate header.
   */
  /* EGP Header structure making a pointer to Packet. */
  egp           = (struct egp_hdr *)((void *)ip + sizeof(struct iphdr) + greoptlen);
  egp->version  = EGPVERSION;
  egp->type     = o->egp.type;
  egp->code     = o->egp.code;
  egp->status   = o->egp.status;
  egp->as       = __RND(o->egp.as);
  egp->sequence = __RND(o->egp.sequence);
  egp->check    = 0;

  offset  = sizeof(struct egp_hdr);

  /* EGP Acquire Header structure. */
  egp_acq        = (struct egp_acq_hdr *)((void *)egp + offset);
  egp_acq->hello = __RND(o->egp.hello);
  egp_acq->poll  = __RND(o->egp.poll);

  offset += sizeof(struct egp_acq_hdr);

  /* Computing the checksum. */
  egp->check    = o->bogus_csum ? random() : cksum(egp, offset);

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
