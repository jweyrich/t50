/* vim: set ts=2 et sw=2 : */
/** @file eigrp.c */
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
#include <netinet/in.h>
#include <t50_defines.h>
#include <t50_config.h>
#include <t50_cksum.h>
#include <t50_memalloc.h>
#include <t50_modules.h>
#include <t50_randomizer.h>

static size_t eigrp_hdr_len(const uint16_t, const uint16_t, const uint8_t, const int);

/**
 * EIGRP packet header configuration.
 *
 * This function configures and sends the EIGRP packet header.
 *
 * @param co Pointer to T50 configuration structure.
 * @param size Pointer to packet size (updated by the function).
 */
void eigrp(const struct config_options *const __restrict__ co, size_t *size)
{
  size_t greoptlen,     /* GRE options size. */
         eigrp_tlv_len, /* EIGRP TLV size. */
         counter;

  in_addr_t dest;       /* EIGRP Destination address */
  uint32_t prefix;      /* EIGRP Prefix */

  /* Packet and Checksum. */
  memptr_t buffer;

  struct iphdr *ip;
  struct eigrp_hdr *eigrp;

  assert(co != NULL);

  greoptlen = gre_opt_len(co);
  prefix = __RND(co->eigrp.prefix);
  eigrp_tlv_len = eigrp_hdr_len(co->eigrp.opcode, co->eigrp.type, prefix, co->eigrp.auth);

  *size = sizeof(struct iphdr)     +
          sizeof(struct eigrp_hdr) +
          eigrp_tlv_len            +
          greoptlen                +
          8;    /* OBS: Ugly workaround! Must change this later! */

  /* Try to reallocate packet, if necessary */
  alloc_packet(*size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, *size, co);

  /* GRE Encapsulation takes place. */
  gre_encapsulation(packet, co,
                    sizeof(struct iphdr)     +
                    sizeof(struct eigrp_hdr) +
                    eigrp_tlv_len);

  /*
   * Please,  be advised that there is no deep information about EIGRP,  no
   * other than EIGRP PCAP files public available.  Due to that I have done
   * a deep analysis using live EIGRP PCAP files to build the EIGRP Packet.
   *
   * There are some really good resources, such as:
   * http://www.protocolbase.net/protocols/protocol_EIGRP.php
   * http://packetlife.net/captures/category/cisco-proprietary/
   * http://oreilly.com/catalog/iprouting/chapter/ch04.html
   *
   * EIGRP Header structure.
   */
  eigrp              = (struct eigrp_hdr *)((unsigned char *)(ip + 1) + greoptlen);
  eigrp->version     = co->eigrp.ver_minor ? co->eigrp.ver_minor : EIGRPVERSION;
  eigrp->opcode      = __RND(co->eigrp.opcode);
  eigrp->flags       = htonl(__RND(co->eigrp.flags));
  eigrp->sequence    = htonl(__RND(co->eigrp.sequence));
  eigrp->acknowledge = co->eigrp.type == EIGRP_TYPE_SEQUENCE ?
                       htonl(__RND(co->eigrp.acknowledge)) : 0;
  eigrp->as          = htonl(__RND(co->eigrp.as));
  eigrp->check       = 0;

  buffer.ptr = eigrp + 1;

  /*
   * Every live EIGRP PCAP file brings Authentication Data TLV first.
   *
   * The Authentication Data TVL must be used only in some cases:
   * 1. IP Internal or External Routes TLV for Update
   * 2. Software Version with Parameter TLVs for Hello
   * 3. Next Multicast Sequence TLV for Hello
   */
  if (co->eigrp.auth)
  {
    if (co->eigrp.opcode  == EIGRP_OPCODE_UPDATE  ||
        (co->eigrp.opcode == EIGRP_OPCODE_HELLO   &&
         (co->eigrp.type  == EIGRP_TYPE_MULTICAST ||
          co->eigrp.type  == EIGRP_TYPE_SOFTWARE)))
    {
      /* NOTE: stemp used to avoid multiple comparisons on loop below */
      size_t stemp;

      stemp = auth_hmac_md5_len(co->eigrp.auth);

      /*
       * Enhanced Interior Gateway Routing Protocol (EIGRP)
       *
       * Authentication Data TLV  (EIGRP Type = 0x0002)
       *
       *    0                   1                   2                   3 3
       *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *   |             Type              |            Length             |
       *   +---------------------------------------------------------------+
       *   |     Authentication Method     |    Authentication Key Size    |
       *   +---------------------------------------------------------------+
       *   |                     Authentication Key ID                     |
       *   +---------------------------------------------------------------+
       *   |                                                               |
       *   +                                                               +
       *   |                          Padding (?)                          |
       *   +                                                               +
       *   |                                                               |
       *   +---------------------------------------------------------------+
       *   |                                                               |
       *   +                                                               +
       *   |                    Authentication Key Block                   |
       *   +                          (MD5 Digest)                         +
       *   |                                                               |
       *   +                                                               +
       *   |                                                               |
       *   +---------------------------------------------------------------+
       */
      *buffer.word_ptr++ = htons(EIGRP_TYPE_AUTH);
      *buffer.word_ptr++ = htons(co->eigrp.length ? co->eigrp.length : EIGRP_TLEN_AUTH);
      *buffer.word_ptr++ = htons(AUTH_TYPE_HMACMD5);
      *buffer.word_ptr++ = htons(stemp);
      *buffer.dword_ptr++ = htonl(__RND(co->eigrp.key_id));

      for (counter = 0; counter < EIGRP_PADDING_BLOCK; counter++)
        *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;

      /*
       * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
       */
      for (counter = 0; counter < stemp; counter++)
        *buffer.byte_ptr++ = RANDOM();
    }
  }

  /*
   * AFAIK,   there are differences when building the EIGRP packet for
   * Update, Request, Query and Reply.  Any EIGRP PCAP file I saw does
   * not carry Paremeter,  Software Version and/or Multicast Sequence,
   * instead, it carries Authentication Data, IP Internal and External
   * Routes or nothing (depends on the EIGRP Type).
   */
  switch (co->eigrp.opcode)
  {
  case EIGRP_OPCODE_UPDATE:
  case EIGRP_OPCODE_REQUEST:
  case EIGRP_OPCODE_QUERY:
  case EIGRP_OPCODE_REPLY:
    if (co->eigrp.type == EIGRP_TYPE_INTERNAL ||
        co->eigrp.type == EIGRP_TYPE_EXTERNAL)
    {
      /*
       * Enhanced Interior Gateway Routing Protocol (EIGRP)
       *
       * IP Internal Routes TLV  (EIGRP Type = 0x0102)
       *
       *    0                   1                   2                   3 3
       *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *   |             Type              |            Length             |
       *   +---------------------------------------------------------------+
       *   |                       Next Hop Address                        |
       *   +---------------------------------------------------------------+
       *   |                             Delay                             |
       *   +---------------------------------------------------------------+
       *   |                           Bandwidth                           |
       *   +---------------------------------------------------------------+
       *   |        Maximum Transmission Unit (MTU)        |   Hop Count   |
       *   +---------------------------------------------------------------+
       *   |  Reliability  |     Load      |           Reserved            |
       *   +---------------------------------------------------------------+
       *   |    Prefix     //
       *   +---------------+
       *
       *   +---------------------------------------------------------------+
       *   //           Destination IP Address(es) (1-4 octets)            |
       *   +---------------------------------------------------------------+
       *
       * IP External Routes TLV  (EIGRP Type = 0x0103)
       *
       *    0                   1                   2                   3 3
       *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *   |             Type              |            Length             |
       *   +---------------------------------------------------------------+
       *   |                       Next Hop Address                        |
       *   +---------------------------------------------------------------+
       *   |                      Originating Router                       |
       *   +---------------------------------------------------------------+
       *   |                Originating Autonomous System                  |
       *   +---------------------------------------------------------------+
       *   |                         Arbitrary TAG                         |
       *   +---------------------------------------------------------------+
       *   |                   External Protocol Metric                    |
       *   +---------------------------------------------------------------+
       *   |           Reserved1           | Ext. Proto ID |     Flags     |
       *   +---------------------------------------------------------------+
       *   |                             Delay                             |
       *   +---------------------------------------------------------------+
       *   |                           Bandwidth                           |
       *   +---------------------------------------------------------------+
       *   |        Maximum Transmission Unit (MTU)        |   Hop Count   |
       *   +---------------------------------------------------------------+
       *   |  Reliability  |     Load      |           Reserved2           |
       *   +---------------------------------------------------------------+
       *   |    Prefix     //
       *   +---------------+
       *
       *   +---------------------------------------------------------------+
       *   //           Destination IP Address(es) (1-4 octets)            |
       *   +---------------------------------------------------------------+
       *
       * The only difference between Internal and External Routes TLVs is 20
       * octets.
       */
      *buffer.word_ptr++ = htons(co->eigrp.type == EIGRP_TYPE_INTERNAL ?
                                 EIGRP_TYPE_INTERNAL : EIGRP_TYPE_EXTERNAL);
      /*
       * For both Internal and External Routes TLV the code must perform
       * an additional step to compute the EIGRP header length,  because
       * it depends on the the EIGRP Prefix, and it can be 1-4 octets.
       */
      *buffer.word_ptr++ = htons(co->eigrp.length ?
                                 co->eigrp.length :
                                 (co->eigrp.type == EIGRP_TYPE_INTERNAL ?
                                  EIGRP_TLEN_INTERNAL :
                                  EIGRP_TLEN_EXTERNAL) +
                                 EIGRP_DADDR_LENGTH(prefix));
      *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->eigrp.next_hop));

      /*
       * The only difference between Internal and External Routes TLVs is 20
       * octets. Building 20 extra octets for IP External Routes TLV.
       */
      if (co->eigrp.type == EIGRP_TYPE_EXTERNAL)
      {
        *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->eigrp.src_router));
        *buffer.dword_ptr++ = htonl(__RND(co->eigrp.src_as));
        *buffer.dword_ptr++ = htonl(__RND(co->eigrp.tag));
        *buffer.dword_ptr++ = htonl(__RND(co->eigrp.proto_metric));
        *buffer.word_ptr++ = co->eigrp.opcode == EIGRP_OPCODE_UPDATE ?
                             FIELD_MUST_BE_ZERO : htons(0x0004);
        *buffer.byte_ptr++ = __RND(co->eigrp.proto_id);
        *buffer.byte_ptr++ = __RND(co->eigrp.ext_flags);
      }

      dest = INADDR_RND(co->eigrp.dest);

      *buffer.dword_ptr++ = htonl(__RND(co->eigrp.delay));
      *buffer.dword_ptr++ = htonl(__RND(co->eigrp.bandwidth));
      *buffer.dword_ptr++ = htonl(__RND(co->eigrp.mtu) << 8);
      *buffer.byte_ptr++ = __RND(co->eigrp.hop_count);
      *buffer.byte_ptr++ = __RND(co->eigrp.reliability);
      *buffer.byte_ptr++ = __RND(co->eigrp.load);
      *buffer.word_ptr++ = co->eigrp.opcode == EIGRP_OPCODE_UPDATE ?
                           FIELD_MUST_BE_ZERO : htons(0x0004);
      *buffer.byte_ptr++ = prefix;
      *buffer.inaddr_ptr++ = EIGRP_DADDR_BUILD(dest, prefix);  // Is this correct?
      buffer.ptr += EIGRP_DADDR_LENGTH(prefix);
    }

    break;

  /*
   * In the other hand,   EIGRP Packet for Hello can carry Paremeter,
   * Software Version, Multicast Sequence or nothing (Acknowledge).
   */
  case EIGRP_OPCODE_HELLO:

    /*
     * AFAIK,  EIGRP TLVs must follow a predefined sequence in order to
     * be built. I am not sure whether any TLV's precedence will impact
     * in the routers'  processing of  EIGRP Packet,  so I am following
     * exactly what I saw on live  EIGRP PCAP files.  Read the code and
     * you will understand what I am talking about.
     */
    switch (co->eigrp.type)
    {
    case EIGRP_TYPE_PARAMETER:
    case EIGRP_TYPE_SOFTWARE:
    case EIGRP_TYPE_MULTICAST:
      /*
       * Enhanced Interior Gateway Routing Protocol (EIGRP)
       *
       * General Parameter TLV (EIGRP Type = 0x0001)
       *
       *    0                   1                   2                   3 3
       *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *   |             Type              |            Length             |
       *   +---------------------------------------------------------------+
       *   |      K1       |      K2       |      K3       |      K4       |
       *   +---------------------------------------------------------------+
       *   |      K5       |    Reserved   |           Hold Time           |
       *   +---------------------------------------------------------------+
       */
      *buffer.word_ptr++ = htons(EIGRP_TYPE_PARAMETER);
      *buffer.word_ptr++ = htons(co->eigrp.length ?
                                 co->eigrp.length : EIGRP_TLEN_PARAMETER);
      *buffer.byte_ptr++ = TEST_BITS(co->eigrp.values, EIGRP_KVALUE_K1) ?
                           __RND(co->eigrp.k1) : co->eigrp.k1;
      *buffer.byte_ptr++ = TEST_BITS(co->eigrp.values, EIGRP_KVALUE_K2) ?
                           __RND(co->eigrp.k2) : co->eigrp.k2;
      *buffer.byte_ptr++ = TEST_BITS(co->eigrp.values, EIGRP_KVALUE_K3) ?
                           __RND(co->eigrp.k3) : co->eigrp.k3;
      *buffer.byte_ptr++ = TEST_BITS(co->eigrp.values, EIGRP_KVALUE_K4) ?
                           __RND(co->eigrp.k4) : co->eigrp.k4;
      *buffer.byte_ptr++ = TEST_BITS(co->eigrp.values, EIGRP_KVALUE_K5) ?
                           __RND(co->eigrp.k5) : co->eigrp.k5;
      *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
      *buffer.word_ptr++ = htons(co->eigrp.hold);

      /* Going to the next TLV, if it needs to do sco-> */
      if (co->eigrp.type == EIGRP_TYPE_SOFTWARE ||
          co->eigrp.type == EIGRP_TYPE_MULTICAST)
      {
        /*
         * Enhanced Interior Gateway Routing Protocol (EIGRP)
         *
         * Software Version TLV (EIGRP Type = 0x0004)
         *
         *    0                   1                   2                   3 3
         *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *   |             Type              |            Length             |
         *   +---------------------------------------------------------------+
         *   |   IOS Major   |   IOS Minor   |  EIGRP Major  |  EIGRP Minor  |
         *   +---------------------------------------------------------------+
         */
        *buffer.word_ptr++ = htons(EIGRP_TYPE_SOFTWARE);
        *buffer.word_ptr++ = htons(co->eigrp.length ?
                                   co->eigrp.length : EIGRP_TLEN_SOFTWARE);
        *buffer.byte_ptr++ = __RND(co->eigrp.ios_major);
        *buffer.byte_ptr++ = __RND(co->eigrp.ios_minor);
        *buffer.byte_ptr++ = __RND(co->eigrp.ver_major);
        *buffer.byte_ptr++ = __RND(co->eigrp.ver_minor);

        /* Going to the next TLV, if it needs to do sco-> */
        if (co->eigrp.type == EIGRP_TYPE_MULTICAST)
        {
          /*
           * Enhanced Interior Gateway Routing Protocol (EIGRP)
           *
           * Sequence TLV (EIGRP Type = 0x0003)
           *
           *    0                   1                   2                   3 3
           *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           *   |             Type              |            Length             |
           *   +---------------------------------------------------------------+
           *   |  Addr Length  //
           *   +---------------+
           *
           *   +---------------------------------------------------------------+
           *   //                         IP Address                           |
           *   +---------------------------------------------------------------+
           */
          *buffer.word_ptr++ = htons(EIGRP_TYPE_SEQUENCE);
          *buffer.word_ptr++ = htons(co->eigrp.length ?
                                     co->eigrp.length : EIGRP_TLEN_SEQUENCE);
          *buffer.byte_ptr++ = sizeof(co->eigrp.address);
          *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->eigrp.address));

          /*
           * Enhanced Interior Gateway Routing Protocol (EIGRP)
           *
           * Next Multicast Sequence TLV (EIGRP Type = 0x0005)
           *
           *    0                   1                   2                   3 3
           *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           *   |             Type              |            Length             |
           *   +---------------------------------------------------------------+
           *   |                    Next Multicast Sequence                    |
           *   +---------------------------------------------------------------+
           */
          *buffer.word_ptr++ = htons(EIGRP_TYPE_MULTICAST);
          *buffer.word_ptr++ = htons(co->eigrp.length ?
                                     co->eigrp.length : EIGRP_TLEN_MULTICAST);
          *buffer.dword_ptr++ = htonl(__RND(co->eigrp.multicast));
        }
      }
    }
  }

  /* Computing the checksum. */
  eigrp->check    = co->bogus_csum ?
                    RANDOM() : cksum(eigrp, buffer.ptr - (void *)eigrp);

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, co, *size);
}

/* EIGRP header size calculation */
size_t eigrp_hdr_len(const uint16_t opcode,
                     const uint16_t type,
                     const uint8_t prefix,
                     const int auth)
{
  /* The code starts with size '0' and it accumulates all the required
   * size if the conditionals match. Otherwise, it returns size '0'. */
  size_t size = 0;

  /*
   * The Authentication Data TVL must be used only in some cases:
   * 1. IP Internal or External Routes TLV for Update
   * 2. Software Version with Parameter TLVs for Hello
   * 3. Next Multicast Sequence TLV for Hello
   */
  if (auth)
  {
    if (opcode  == EIGRP_OPCODE_UPDATE  ||
        (opcode == EIGRP_OPCODE_HELLO   &&
         (type  == EIGRP_TYPE_MULTICAST ||
          type  == EIGRP_TYPE_SOFTWARE)))
      size += EIGRP_TLEN_AUTH;
  }

  /*
   * AFAIK,   there are differences when building the EIGRP packet for
   * Update, Request, Query and Reply.  Any EIGRP PCAP file I saw does
   * not carry Parameter,  Software Version and/or Multicast Sequence,
   * instead, it carries Authentication Data, IP Internal and External
   * Routes or nothing (depends on the EIGRP Type).
   */
  switch (opcode)
  {
  case EIGRP_OPCODE_UPDATE:
  case EIGRP_OPCODE_REQUEST:
  case EIGRP_OPCODE_QUERY:
  case EIGRP_OPCODE_REPLY:

    /*
     * For both Internal and External Routes TLV the code must perform
     * an additional step to compute the EIGRP header length,  because
     * it depends on the the EIGRP Prefix, and it can be 1-4 octets.
     */
    switch (type)
    {
    case EIGRP_TYPE_INTERNAL:
      size += EIGRP_TLEN_INTERNAL;
      size += EIGRP_DADDR_LENGTH(prefix);
      break;

    case EIGRP_TYPE_EXTERNAL:
      size += EIGRP_TLEN_EXTERNAL;
      size += EIGRP_DADDR_LENGTH(prefix);
    }

    break;

  /*
   * In the other hand, EIGRP Packet for Hello can carry Parameter,
   * Software Version, Multicast Sequence or nothing (Acknowledge).
   */
  case EIGRP_OPCODE_HELLO:

    /*
     * AFAIK,  EIGRP TLVs must follow a predefined sequence in order to
     * be built. I am not sure whether any TLV's precedence will impact
     * in the routers'  processing of  EIGRP Packet,  so I am following
     * exactly what I saw on live  EIGRP PCAP files.  Read the code and
     * you will understand what I am talking about.
     */
    switch (type)
    {
    case EIGRP_TYPE_MULTICAST:
      size += EIGRP_TLEN_MULTICAST;
      size += EIGRP_TLEN_SEQUENCE;

    case EIGRP_TYPE_SOFTWARE:
      size += EIGRP_TLEN_SOFTWARE;

    case EIGRP_TYPE_PARAMETER:
      size += EIGRP_TLEN_PARAMETER;
      break;
    }
  }

  return size;
}



