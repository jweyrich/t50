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
void igmpv3(const struct config_options * const __restrict__ co, size_t *size)
{
  size_t greoptlen,   /* GRE options size. */
         counter;

  /* Packet and Checksum. */
  mptr_t buffer;

#ifdef __HAVE_DEBUG__
  void *__pstart, *__pend;
#endif

  struct iphdr * ip;

  /* IGMPv3 Query header, IGMPv3 Report header and IGMPv3 GREC header. */
  struct igmpv3_query * igmpv3_query;
  struct igmpv3_report * igmpv3_report;
  struct igmpv3_grec * igmpv3_grec;

  assert(co != NULL);

  greoptlen = gre_opt_len(co->gre.options, co->encapsulated);
  *size = sizeof(struct iphdr) +
    greoptlen            +
    igmpv3_hdr_len(co->igmp.type, co->igmp.sources);

#ifdef __HAVE_DEBUG__
  PRINT_CALC_SIZE(*size);
#endif

  /* Try to reallocate packet, if necessary */
  alloc_packet(*size);

#ifdef __HAVE_DEBUG__
  __pstart = packet;
#endif

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, *size, co);

  /* GRE Encapsulation takes place. */
  gre_encapsulation(packet, co,
        sizeof(struct iphdr) +
        igmpv3_hdr_len(co->igmp.type, co->igmp.sources));

  /* Identifying the IGMP Type and building it. */
  if (co->igmp.type == IGMPV3_HOST_MEMBERSHIP_REPORT)
  {
    /* IGMPv3 Report Header structure making a pointer to Packet. */
    igmpv3_report           = (struct igmpv3_report *)((void *)ip + sizeof(struct iphdr) + greoptlen);
    igmpv3_report->type     = co->igmp.type;
    igmpv3_report->resv1    = FIELD_MUST_BE_ZERO;
    igmpv3_report->resv2    = FIELD_MUST_BE_ZERO;
    igmpv3_report->ngrec    = htons(1);
    igmpv3_report->csum     = 0;

    /* IGMPv3 Group Record Header structure making a pointer to Checksum. */
    igmpv3_grec                = (void *)igmpv3_report + sizeof(struct igmpv3_report);
    igmpv3_grec->grec_type     = __RND(co->igmp.grec_type);
    igmpv3_grec->grec_auxwords = FIELD_MUST_BE_ZERO;
    igmpv3_grec->grec_nsrcs    = htons(co->igmp.sources);
    igmpv3_grec->grec_mca      = INADDR_RND(co->igmp.grec_mca);

    /* Dealing with source address(es). */
    buffer.ptr = (void *)igmpv3_grec + sizeof(struct igmpv3_grec);
    for (counter = 0; counter < co->igmp.sources; counter++)
      *buffer.inaddr_ptr++ = INADDR_RND(co->igmp.address[counter]);

    /* Computing the checksum. */
    igmpv3_report->csum     = co->bogus_csum ?
      random() :
      cksum(igmpv3_report, 
        sizeof(struct igmpv3_report) + 
        sizeof(struct igmpv3_grec)   + 
        IGMPV3_TLEN_NSRCS(co->igmp.sources));
  }
  else
  {
    /* IGMPv3 Query Header structure making a pointer to Packet. */
    igmpv3_query           = (struct igmpv3_query *)((void *)ip + sizeof(struct iphdr) + greoptlen);
    igmpv3_query->type     = co->igmp.type;
    igmpv3_query->code     = co->igmp.code;
    igmpv3_query->group    = INADDR_RND(co->igmp.group);
    igmpv3_query->suppress = co->igmp.suppress;
    igmpv3_query->qrv      = __RND(co->igmp.qrv);
    igmpv3_query->qqic     = __RND(co->igmp.qqic);
    igmpv3_query->nsrcs    = htons(co->igmp.sources);
    igmpv3_query->csum     = 0;

    /* Dealing with source address(es). */
    buffer.ptr = (void *)igmpv3_query + sizeof(struct igmpv3_query);
    for (counter = 0; counter < co->igmp.sources; counter++)
      *buffer.inaddr_ptr++ = INADDR_RND(co->igmp.address[counter]);

    /* Computing the checksum. */
    igmpv3_query->csum     = co->bogus_csum ?
      random() :
      cksum(igmpv3_query, 
        buffer.ptr - (void *)igmpv3_query);
  }

#ifdef __HAVE_DEBUG__
  __pend = buffer.ptr;
  PRINT_PTR_DIFF(__pstart, __pend);
#endif

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, co, *size);
}
