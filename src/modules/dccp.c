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

/* Function Name: DCCP packet header configuration.

Description:   This function configures and sends the DCCP packet header.

Targets:       N/A */
int dccp(const socket_t fd, const struct config_options *o)
{
  size_t greoptlen,   /* GRE options size. */
         dccp_length, /* DCCP header length. */
         dccp_ext_length, /* DCCP Extended Sequence Number length. */
         packet_size,
         offset;

  /* Packet and Checksum. */
  void *buffer_ptr;

  /* Socket address and IP heade. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* GRE Encapsulated IP Header. */
  struct iphdr * gre_ip;

  /* DCCP header and PSEUDO header. */
  struct dccp_hdr * dccp;
  struct psdhdr * pseudo;

  /* DCCP Headers. */
  struct dccp_hdr_ext * dccp_ext;
  struct dccp_hdr_request * dccp_req;
  struct dccp_hdr_response * dccp_res;
  struct dccp_hdr_ack_bits * dccp_ack;
  struct dccp_hdr_reset * dccp_rst;

  assert(o != NULL);

  greoptlen = gre_opt_len(o->gre.options, o->encapsulated);
  dccp_length = dccp_packet_hdr_len(o->dccp.type);
  dccp_ext_length = (o->dccp.ext ? sizeof(struct dccp_hdr_ext) : 0);
  packet_size = sizeof(struct iphdr) + 
    greoptlen               + 
    sizeof(struct dccp_hdr) + 
    dccp_ext_length         + 
    dccp_length;

  /* Try to reallocate packet, if necessary */
  alloc_packet(packet_size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, packet_size, o);

  /* Prepare GRE encapsulation, if needed */
  gre_ip = gre_encapsulation(packet, o, 
        sizeof(struct iphdr) + 
        sizeof(struct dccp_hdr) + 
        dccp_ext_length         + 
        dccp_length);

  /* DCCP Header structure making a pointer to Packet. */
  dccp                 = (struct dccp_hdr *)((void *)ip + sizeof(struct iphdr) + greoptlen);
  dccp->dccph_sport    = htons(IPPORT_RND(o->source)); 
  dccp->dccph_dport    = htons(IPPORT_RND(o->dest));

  /*
   * Datagram Congestion Control Protocol (DCCP) (RFC 4340)
   *
   *   Data Offset: 8 bits
   *     The offset from the start of the packet's DCCP header to the start
   *     of its  application data area, in 32-bit words.  The receiver MUST
   *     ignore packets whose Data Offset is smaller than the minimum-sized
   *     header for the given Type or larger than the DCCP packet itself.
   */
  dccp->dccph_doff    = o->dccp.doff ? 
    o->dccp.doff : (sizeof(struct dccp_hdr) + dccp_length + dccp_ext_length) / 4;
  dccp->dccph_type    = o->dccp.type;
  dccp->dccph_ccval   = __RND(o->dccp.ccval);

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
  dccp->dccph_cscov    = o->dccp.cscov ? 
    (o->dccp.cscov - 1) * 4 : (o->bogus_csum ? random() : o->dccp.cscov);

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
  dccp->dccph_x        = o->dccp.ext;
  dccp->dccph_seq      = htons(__RND(o->dccp.sequence_01));
  dccp->dccph_seq2     = o->dccp.ext ? 0 : __RND(o->dccp.sequence_02);
  dccp->dccph_checksum = 0;

  offset  = sizeof(struct dccp_hdr);

  /* NOTE: Not using union 'mptr_t' this time!!! */
  buffer_ptr = (void *)dccp + offset;

  /* DCCP Extended Header structure making a pointer to Checksum. */
  if (o->dccp.ext)
  {
    dccp_ext = (struct dccp_hdr_ext *)buffer_ptr;
    dccp_ext->dccph_seq_low = htonl(__RND(o->dccp.sequence_03));

    offset += sizeof(struct dccp_hdr_ext);
  }

  /* Identifying the DCCP Type and building it. */
  switch (o->dccp.type)
  {
    case DCCP_PKT_REQUEST:
      /* DCCP Request Header structure making a pointer to Checksum. */
      dccp_req = (struct dccp_hdr_request *)(buffer_ptr + (offset - sizeof(struct dccp_hdr)));
      dccp_req->dccph_req_service = htonl(__RND(o->dccp.service));

      offset += sizeof(struct dccp_hdr_request);
      break;

    case DCCP_PKT_RESPONSE:
      /* DCCP Response Header structure making a pointer to Checksum. */
      dccp_res = (struct dccp_hdr_response *)(buffer_ptr + (offset - sizeof(struct dccp_hdr)));
      dccp_res->dccph_resp_ack.dccph_reserved1   = FIELD_MUST_BE_ZERO;
      dccp_res->dccph_resp_ack.dccph_ack_nr_high = htons(__RND(o->dccp.acknowledge_01));
      dccp_res->dccph_resp_ack.dccph_ack_nr_low  = htonl(__RND(o->dccp.acknowledge_02));
      dccp_res->dccph_resp_service               = htonl(__RND(o->dccp.service));

      offset += sizeof(struct dccp_hdr_response);
    case DCCP_PKT_DATA:
      break;

    case DCCP_PKT_DATAACK:
    case DCCP_PKT_ACK:
    case DCCP_PKT_SYNC:
    case DCCP_PKT_SYNCACK:
    case DCCP_PKT_CLOSE:
    case DCCP_PKT_CLOSEREQ:
      /* DCCP Acknowledgment Header structure making a pointer to Checksum. */
      dccp_ack = (struct dccp_hdr_ack_bits *)(buffer_ptr + (offset - sizeof(struct dccp_hdr)));
      dccp_ack->dccph_reserved1   = FIELD_MUST_BE_ZERO;
      dccp_ack->dccph_ack_nr_high = htons(__RND(o->dccp.acknowledge_01));
      /* Until DCCP Options implementation. */
      if (o->dccp.type == DCCP_PKT_DATAACK ||
          o->dccp.type == DCCP_PKT_ACK)
        dccp_ack->dccph_ack_nr_low  = htonl(0x00000001);
      else
        dccp_ack->dccph_ack_nr_low  = htonl(__RND(o->dccp.acknowledge_02));

      offset += sizeof(struct dccp_hdr_ack_bits);
      break;

    default:
      /* DCCP Reset Header structure making a pointer to Checksum. */
      dccp_rst = (struct dccp_hdr_reset *)(buffer_ptr + (offset - sizeof(struct dccp_hdr)));
      dccp_rst->dccph_reset_ack.dccph_reserved1   = FIELD_MUST_BE_ZERO;
      dccp_rst->dccph_reset_ack.dccph_ack_nr_high = htons(__RND(o->dccp.acknowledge_01));
      dccp_rst->dccph_reset_ack.dccph_ack_nr_low  = htonl(__RND(o->dccp.acknowledge_02));
      dccp_rst->dccph_reset_code                  = __RND(o->dccp.rst_code);

      offset += sizeof(struct dccp_hdr_reset);
      break;
  }

  /* PSEUDO Header structure??? */
  pseudo = (struct psdhdr *)(buffer_ptr + (offset - sizeof(struct dccp_hdr)));
  pseudo->saddr = o->encapsulated ? gre_ip->saddr : ip->saddr;
  pseudo->daddr = o->encapsulated ? gre_ip->daddr : ip->daddr;
  pseudo->zero  = 0;
  pseudo->protocol = o->ip.protocol;
  pseudo->len      = htons(offset);

  offset += sizeof(struct psdhdr);

  /* Computing the checksum. */
  dccp->dccph_checksum = o->bogus_csum ? 
    random() : 
    cksum(dccp, offset);

  /* Finish GRE encapsulation, if needed */
  gre_checksum(packet, o, packet_size);

  /* Setting SOCKADDR structure. */
  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(IPPORT_RND(o->dest));
  sin.sin_addr.s_addr = o->ip.daddr;

  /* Sending Packet. */
  if (sendto(fd, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
    return 1;

  return 0;
}
