/* vim: set ts=2 et sw=2 : */
/** @file dccp.c */
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
#include <linux/dccp.h>
#include <t50_defines.h>
#include <t50_config.h>
#include <t50_cksum.h>
#include <t50_memalloc.h>
#include <t50_modules.h>
#include <t50_randomizer.h>

/**
 * DCCP packet header configuration.
 *
 * This function configures and sends the DCCP packet header.
 *
 * @param co Pointer to T50 configuration structure.
 * @param size Pointer to packet size (updated by the function).
 */
void dccp(const struct config_options *const __restrict__ co, size_t *size)
{
  size_t greoptlen,   /* GRE options size. */
         dccp_length, /* DCCP header length. */
         dccp_ext_length; /* DCCP Extended Sequence Number length. */

  /* Packet and Checksum. */
  void *buffer_ptr;

  struct iphdr *ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr *gre_ip;

  /* DCCP header and PSEUDO header. */
  struct dccp_hdr *dccp;
  struct psdhdr *pseudo;

  /* DCCP Headers. */
  struct dccp_hdr_ext *dccp_ext;
  struct dccp_hdr_request *dccp_req;
  struct dccp_hdr_response *dccp_res;
  struct dccp_hdr_ack_bits *dccp_ack;
  struct dccp_hdr_reset *dccp_rst;

  assert(co != NULL);

  greoptlen = gre_opt_len(co);
  dccp_length = dccp_packet_hdr_len(co->dccp.type);
  dccp_ext_length = (co->dccp.ext ? sizeof(struct dccp_hdr_ext) : 0);

  *size = sizeof(struct iphdr)    +
          sizeof(struct dccp_hdr) +
          sizeof(struct psdhdr)   +
          dccp_ext_length         +
          dccp_length             +
          greoptlen;

  /* Try to reallocate packet, if necessary */
  alloc_packet(*size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, *size, co);

  /* Prepare GRE encapsulation, if needed */
  gre_ip = gre_encapsulation(packet, co,
                             sizeof(struct iphdr)    +
                             sizeof(struct dccp_hdr) +
                             dccp_ext_length         +
                             dccp_length);

  /* DCCP Header structure making a pointer to Packet. */
  dccp                 = (struct dccp_hdr *)((unsigned char *)(ip + 1) + greoptlen);
  dccp->dccph_sport    = htons(IPPORT_RND(co->source));
  dccp->dccph_dport    = htons(IPPORT_RND(co->dest));

  /*
   * Datagram Congestion Control Protocol (DCCP) (RFC 4340)
   *
   *   Data Offset: 8 bits
   *     The offset from the start of the packet's DCCP header to the start
   *     of its  application data area, in 32-bit words.  The receiver MUST
   *     ignore packets whose Data Offset is smaller than the minimum-sized
   *     header for the given Type or larger than the DCCP packet itself.
   */
  dccp->dccph_doff    = co->dccp.doff ?
                        co->dccp.doff : (sizeof(struct dccp_hdr) + dccp_length + dccp_ext_length) / 4;
  dccp->dccph_type    = co->dccp.type;
  dccp->dccph_ccval   = __RND(co->dccp.ccval);

  /*
   * Datagram Congestion Control Protocol (DCCP) (RFC 4340)
   *
   * 9.2.  Header Checksum Coverage Field
   *
   *   The  Checksum Coverage field in the DCCP generic header (see Section
   *   5.1)  specifies what parts of the packet are covered by the Checksum
   *   field, as follows:
   *
   *   CsCov = 0      The  Checksum  field  covers  the  DCCP  header, DCCP
   *                  options,    network-layer   pseudoheader,   and   all
   *                  application  data  in the packet,  possibly padded on
   *                  the right with zeros to an even number of bytes.
   *
   *   CsCov = 1-15   The  Checksum  field  covers  the  DCCP  header, DCCP
   *                  options,  network-layer pseudoheader, and the initial
   *                  (CsCov-1)*4 bytes of the packet's application data.
   */
  dccp->dccph_cscov    = co->dccp.cscov ?
                         (co->dccp.cscov - 1) * 4 :
                         (co->bogus_csum ? (uint8_t)(RANDOM() & 0xf) : co->dccp.cscov);

  /*
   * Datagram Congestion Control Protocol (DCCP) (RFC 4340)
   *
   * 5.1.  Generic Header
   *
   *   The DCCP generic header takes different forms depending on the value
   *   of X,  the Extended Sequence Numbers bit.  If X is one, the Sequence
   *   Number field is 48 bits long, and the generic header takes 16 bytes,
   *   as follows.
   *
   *        0                   1                   2                   3
   *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |          Source Port          |           Dest Port           |
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |  Data Offset  | CCVal | CsCov |           Checksum            |
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |     |       |X|               |                               .
   *       | Res | Type  |=|   Reserved    |  Sequence Number (high bits)  .
   *       |     |       |1|               |                               .
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       .                  Sequence Number (low bits)                   |
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *
   *   If  X  is  zero,  only the low 24 bits of the  Sequence  Number  are
   *   transmitted, and the generic header is 12 bytes long.
   *
   *        0                   1                   2                   3
   *        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |          Source Port          |           Dest Port           |
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |  Data Offset  | CCVal | CsCov |           Checksum            |
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   *       |     |       |X|                                               |
   *       | Res | Type  |=|          Sequence Number (low bits)           |
   *       |     |       |0|                                               |
   *       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */
  dccp->dccph_x        = co->dccp.ext;
  dccp->dccph_seq      = htons(__RND(co->dccp.sequence_01));
  dccp->dccph_seq2     = co->dccp.ext ? 0 : __RND(co->dccp.sequence_02);
  dccp->dccph_checksum = 0;

  /* NOTE: Not using union 'memptr_t' this time!!! */
  buffer_ptr = dccp + 1;

  /* DCCP Extended Header structure making a pointer to Checksum. */
  if (co->dccp.ext)
  {
    dccp_ext = buffer_ptr;
    dccp_ext->dccph_seq_low = htonl(__RND(co->dccp.sequence_03));

    buffer_ptr = dccp_ext + 1;
  }

  /* Identifying the DCCP Type and building it. */
  switch (co->dccp.type)
  {
  case DCCP_PKT_REQUEST:
    /* DCCP Request Header structure making a pointer to Checksum. */
    dccp_req = buffer_ptr;
    dccp_req->dccph_req_service = htonl(__RND(co->dccp.service));

    buffer_ptr = dccp_req + 1;
    break;

  case DCCP_PKT_RESPONSE:
    /* DCCP Response Header structure making a pointer to Checksum. */
    dccp_res = buffer_ptr;
    dccp_res->dccph_resp_ack.dccph_reserved1   = FIELD_MUST_BE_ZERO;
    dccp_res->dccph_resp_ack.dccph_ack_nr_high = htons(__RND(co->dccp.acknowledge_01));
    dccp_res->dccph_resp_ack.dccph_ack_nr_low  = htonl(__RND(co->dccp.acknowledge_02));
    dccp_res->dccph_resp_service               = htonl(__RND(co->dccp.service));

    buffer_ptr = dccp_res + 1;
  case DCCP_PKT_DATA:
    break;

  case DCCP_PKT_DATAACK:
  case DCCP_PKT_ACK:
  case DCCP_PKT_SYNC:
  case DCCP_PKT_SYNCACK:
  case DCCP_PKT_CLOSE:
  case DCCP_PKT_CLOSEREQ:
    /* DCCP Acknowledgment Header structure making a pointer to Checksum. */
    dccp_ack = buffer_ptr;
    dccp_ack->dccph_reserved1   = FIELD_MUST_BE_ZERO;
    dccp_ack->dccph_ack_nr_high = htons(__RND(co->dccp.acknowledge_01));

    /* Until DCCP Options implementation. */
    if (co->dccp.type == DCCP_PKT_DATAACK ||
        co->dccp.type == DCCP_PKT_ACK)
      dccp_ack->dccph_ack_nr_low  = htonl(1);
    else
      dccp_ack->dccph_ack_nr_low  = htonl(__RND(co->dccp.acknowledge_02));

    buffer_ptr = dccp_ack + 1;
    break;

  default:
    /* DCCP Reset Header structure making a pointer to Checksum. */
    dccp_rst = buffer_ptr;
    dccp_rst->dccph_reset_ack.dccph_reserved1   = FIELD_MUST_BE_ZERO;
    dccp_rst->dccph_reset_ack.dccph_ack_nr_high = htons(__RND(co->dccp.acknowledge_01));
    dccp_rst->dccph_reset_ack.dccph_ack_nr_low  = htonl(__RND(co->dccp.acknowledge_02));
    dccp_rst->dccph_reset_code                  = __RND(co->dccp.rst_code);

    buffer_ptr = dccp_rst + 1;
    break;
  }

  /* PSEUDO Header structure??? */
  pseudo = buffer_ptr;
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
  pseudo->len      = htons((short)(buffer_ptr - (void *)dccp));

  /* Computing the checksum. */
  dccp->dccph_checksum = co->bogus_csum ? RANDOM() :
                         cksum(dccp, (unsigned char *)(pseudo + 1) - (unsigned char *)dccp);

  /* Finish GRE encapsulation, if needed */
  gre_checksum(packet, co, *size);
}
