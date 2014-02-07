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

/* Function Name: IGMPv3 packet header configuration.
Description:   This function configures and sends the IGMPv3 packet header. */
int igmpv3(const socket_t fd, const struct config_options *o)
{
  /* GRE options size. */
  size_t greoptlen = gre_opt_len(o->gre.options, o->encapsulated);

  /* Packet size. */
  const uint32_t packet_size = sizeof(struct iphdr) + 
    greoptlen            + 
    igmpv3_hdr_len(o->igmp.type, o->igmp.sources);

  /* Checksum offset, GRE offset and Counter. */
  uint32_t offset, counter;

  /* Packet and Checksum. */
  uint8_t *checksum;

  /* Socket address and IP header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* IGMPv3 Query header, IGMPv3 Report header and IGMPv3 GREC header. */
  struct igmpv3_query * igmpv3_query;
  struct igmpv3_report * igmpv3_report;
  struct igmpv3_grec * igmpv3_grec;

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
        igmpv3_hdr_len(o->igmp.type, o->igmp.sources));

  /* Identifying the IGMP Type and building it. */
  if (o->igmp.type == IGMPV3_HOST_MEMBERSHIP_REPORT)
  {
    /* IGMPv3 Report Header structure making a pointer to Packet. */
    igmpv3_report           = (struct igmpv3_report *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
    igmpv3_report->type     = o->igmp.type;
    igmpv3_report->resv1    = FIELD_MUST_BE_ZERO;
    igmpv3_report->resv2    = FIELD_MUST_BE_ZERO;
    igmpv3_report->ngrec    = htons(1);
    igmpv3_report->csum     = 0;
    /* Computing the Checksum offset. */
    offset  = sizeof(struct igmpv3_report);

    /* Storing both Checksum and Packet. */
    checksum = (uint8_t *)igmpv3_report + offset;

    /* IGMPv3 Group Record Header structure making a pointer to Checksum. */
    igmpv3_grec                = (struct igmpv3_grec *)(checksum + (offset - sizeof(struct igmpv3_report)));
    igmpv3_grec->grec_type     = __8BIT_RND(o->igmp.grec_type);
    igmpv3_grec->grec_auxwords = FIELD_MUST_BE_ZERO;
    igmpv3_grec->grec_nsrcs    = htons(o->igmp.sources);
    igmpv3_grec->grec_mca      = INADDR_RND(o->igmp.grec_mca);
    checksum += sizeof(struct igmpv3_grec);
    /* Computing the Checksum offset. */
    offset += sizeof(struct igmpv3_grec);
    /* Dealing with source address(es). */
    for(counter = 0 ; counter < o->igmp.sources ; counter++)
    {
      *((in_addr_t *)checksum) = INADDR_RND(o->igmp.address[counter]);
      checksum += sizeof(in_addr_t);
    }
    /* Computing the Checksum offset. */
    offset += IGMPV3_TLEN_NSRCS(o->igmp.sources);
    /* Computing the checksum. */
    igmpv3_report->csum     = o->bogus_csum ? 
      __16BIT_RND(0) : 
      cksum((uint16_t *)igmpv3_report, offset);
  }
  else
  {
    /* IGMPv3 Query Header structure making a pointer to Packet. */
    igmpv3_query           = (struct igmpv3_query *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
    igmpv3_query->type     = o->igmp.type;
    igmpv3_query->code     = o->igmp.code;
    igmpv3_query->group    = INADDR_RND(o->igmp.group);
    igmpv3_query->suppress = o->igmp.suppress;
    igmpv3_query->qrv      = __3BIT_RND(o->igmp.qrv);
    igmpv3_query->qqic     = __8BIT_RND(o->igmp.qqic);
    igmpv3_query->nsrcs    = htons(o->igmp.sources);
    igmpv3_query->csum     = 0;
    /* Computing the Checksum offset. */
    offset  = sizeof(struct igmpv3_query);

    /* Storing both Checksum and Packet. */
    checksum = (uint8_t *)igmpv3_query + offset;

    /* Dealing with source address(es). */
    for(counter = 0 ; counter < o->igmp.sources ; counter++)
    {
      *((in_addr_t *)checksum) = INADDR_RND(o->igmp.address[counter]);
      checksum += sizeof(in_addr_t);
    }

    /* Computing the Checksum offset. */
    offset += IGMPV3_TLEN_NSRCS(o->igmp.sources);
    /* Computing the checksum. */
    igmpv3_query->csum     = o->bogus_csum ? 
      __16BIT_RND(0) : 
      cksum((uint16_t *)igmpv3_query, offset);
  }

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, o, packet_size);

  /* Sending Packet. */
  if (sendto(fd, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
    return 1;

  return 0;
}
