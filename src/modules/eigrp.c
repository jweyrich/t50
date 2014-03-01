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

/*
 * prototypes.
 */
static  size_t eigrp_hdr_len(const uint16_t, const uint16_t, const uint8_t, const uint32_t);

/* Function Name: EIGRP packet header configuration.

Description:   This function configures and sends the EIGRP packet header.

Targets:       N/A */
int eigrp(const socket_t fd, const struct config_options *o)
{
  size_t greoptlen,     /* GRE options size. */
         eigrp_tlv_len, /* EIGRP TLV size. */
         packet_size,
         offset,
         counter;

  in_addr_t dest;       /* EIGRP Destination address */
  uint32_t prefix;      /* EIGRP Prefix */

  /* Packet and Checksum. */
  mptr_t buffer;

  /* Socket address and IP header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* EIGRP header. */
  struct eigrp_hdr * eigrp;

  assert(o != NULL);

  greoptlen = gre_opt_len(o->gre.options, o->encapsulated);
  prefix = __5BIT_RND(o->eigrp.prefix);
  eigrp_tlv_len = eigrp_hdr_len(o->eigrp.opcode, o->eigrp.type, prefix, o->eigrp.auth);
  packet_size = sizeof(struct iphdr)     + 
    greoptlen                + 
    sizeof(struct eigrp_hdr) + 
    eigrp_tlv_len;

  /* Try to reallocate packet, if necessary */
  alloc_packet(packet_size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, packet_size, o);

  /* GRE Encapsulation takes place. */
  gre_encapsulation(packet, o, 
        sizeof(struct iphdr) + 
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
  eigrp              = (struct eigrp_hdr *)((void *)ip + sizeof(struct iphdr) + greoptlen);
  eigrp->version     = o->eigrp.ver_minor ? o->eigrp.ver_minor : EIGRPVERSION;
  eigrp->opcode      = __8BIT_RND(o->eigrp.opcode);
  eigrp->flags       = htonl(__32BIT_RND(o->eigrp.flags));
  eigrp->sequence    = htonl(__32BIT_RND(o->eigrp.sequence));
  eigrp->acknowledge = o->eigrp.type == EIGRP_TYPE_SEQUENCE ? 
    htonl(__32BIT_RND(o->eigrp.acknowledge)) : 0;
  eigrp->as          = htonl(__32BIT_RND(o->eigrp.as));
  eigrp->check       = 0;

  offset  = sizeof(struct eigrp_hdr);

  buffer.ptr = (void *)eigrp + offset;

  /*
   * Every live EIGRP PCAP file brings Authentication Data TLV first.
   *
   * The Authentication Data TVL must be used only in some cases:
   * 1. IP Internal or External Routes TLV for Update
   * 2. Software Version with Parameter TLVs for Hello
   * 3. Next Multicast Sequence TLV for Hello
   */
  if (o->eigrp.auth)
  {
    if (o->eigrp.opcode == EIGRP_OPCODE_UPDATE  ||
        (o->eigrp.opcode == EIGRP_OPCODE_HELLO   &&
         (o->eigrp.type   == EIGRP_TYPE_MULTICAST ||
          o->eigrp.type   == EIGRP_TYPE_SOFTWARE)))
    {
      /* NOTE: stemp used to avoid multiple comparisons on loop below */
      size_t stemp;

      stemp = auth_hmac_md5_len(o->eigrp.auth);

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
      *buffer.word_ptr++ = htons(o->eigrp.length ? o->eigrp.length : EIGRP_TLEN_AUTH);
      *buffer.word_ptr++ = htons(AUTH_TYPE_HMACMD5);
      *buffer.word_ptr++ = htons(stemp);
      *buffer.dword_ptr++ = htonl(__32BIT_RND(o->eigrp.key_id));

      for (counter = 0; counter < EIGRP_PADDING_BLOCK; counter++)
        *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;

      /*
       * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
       */
      for (counter = 0; counter < stemp; counter++)
        *buffer.byte_ptr++ = __8BIT_RND(0);

			/* FIXME: Is this correct?! 
                The code, above seems to use a variable size for digest (stemp)
                and length (if o->eigrp_length != 0). */
      offset += EIGRP_TLEN_AUTH;
    }
  }

  /*
   * AFAIK,   there are differences when building the EIGRP packet for
   * Update, Request, Query and Reply.  Any EIGRP PCAP file I saw does
   * not carry Paremeter,  Software Version and/or Multicast Sequence,
   * instead, it carries Authentication Data, IP Internal and External
   * Routes or nothing (depends on the EIGRP Type).
   */
  if (o->eigrp.opcode == EIGRP_OPCODE_UPDATE   ||
      o->eigrp.opcode == EIGRP_OPCODE_REQUEST  ||
      o->eigrp.opcode == EIGRP_OPCODE_QUERY    ||
      o->eigrp.opcode == EIGRP_OPCODE_REPLY)
  {
    if (o->eigrp.type == EIGRP_TYPE_INTERNAL ||
        o->eigrp.type == EIGRP_TYPE_EXTERNAL)
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
      *buffer.word_ptr++ = htons(o->eigrp.type == EIGRP_TYPE_INTERNAL ? 
          EIGRP_TYPE_INTERNAL : EIGRP_TYPE_EXTERNAL);
      /*
       * For both Internal and External Routes TLV the code must perform
       * an additional step to compute the EIGRP header length,  because 
       * it depends on the the EIGRP Prefix, and it can be 1-4 octets.
       */
      *buffer.word_ptr++ = htons(o->eigrp.length ? 
          o->eigrp.length : 
          (o->eigrp.type == EIGRP_TYPE_INTERNAL ? 
           EIGRP_TLEN_INTERNAL : 
           EIGRP_TLEN_EXTERNAL) + 
          EIGRP_DADDR_LENGTH(prefix));
      *buffer.inaddr_ptr++ = INADDR_RND(o->eigrp.next_hop);
      /*
       * The only difference between Internal and External Routes TLVs is 20
       * octets. Building 20 extra octets for IP External Routes TLV.
       */
      if (o->eigrp.type == EIGRP_TYPE_EXTERNAL)
      {
        *buffer.inaddr_ptr++ = INADDR_RND(o->eigrp.src_router);
        *buffer.dword_ptr++ = htonl(__32BIT_RND(o->eigrp.src_as));
        *buffer.dword_ptr++ = htonl(__32BIT_RND(o->eigrp.tag));
        *buffer.dword_ptr++ = htonl(__32BIT_RND(o->eigrp.proto_metric));
        *buffer.word_ptr++ = o->eigrp.opcode == EIGRP_OPCODE_UPDATE ? 
          FIELD_MUST_BE_ZERO : htons(0x0004);
        *buffer.byte_ptr++ = __8BIT_RND(o->eigrp.proto_id);
        *buffer.byte_ptr++ = __8BIT_RND(o->eigrp.ext_flags);
      }

      dest = INADDR_RND(o->eigrp.dest);

      *buffer.dword_ptr++ = htonl(__32BIT_RND(o->eigrp.delay));
      *buffer.dword_ptr++ = htonl(__32BIT_RND(o->eigrp.bandwidth));
      *buffer.dword_ptr++ = htonl(__24BIT_RND(o->eigrp.mtu) << 8);
      *buffer.byte_ptr++ = __8BIT_RND(o->eigrp.hop_count);
      *buffer.byte_ptr++ = __8BIT_RND(o->eigrp.reliability);
      *buffer.byte_ptr++ = __8BIT_RND(o->eigrp.load);
      *buffer.word_ptr++ = o->eigrp.opcode == EIGRP_OPCODE_UPDATE ? 
        FIELD_MUST_BE_ZERO : htons(0x0004);
      *buffer.byte_ptr++ = prefix;
      *buffer.inaddr_ptr++ = EIGRP_DADDR_BUILD(dest, prefix);
      buffer.ptr += EIGRP_DADDR_LENGTH(prefix);

      offset += (o->eigrp.type == EIGRP_TYPE_INTERNAL ? 
          EIGRP_TLEN_INTERNAL : 
          EIGRP_TLEN_EXTERNAL) + 
        EIGRP_DADDR_LENGTH(prefix);
    }
    /*
     * In the other hand,   EIGRP Packet for Hello can carry Paremeter, 
     * Software Version, Multicast Sequence or nothing (Acknowledge).
     */
  }
  else if (o->eigrp.opcode == EIGRP_OPCODE_HELLO)
  {
    /*
     * AFAIK,  EIGRP TLVs must follow a predefined sequence in order to
     * be built. I am not sure whether any TLV's precedence will impact
     * in the routers'  processing of  EIGRP Packet,  so I am following 
     * exactly what I saw on live  EIGRP PCAP files.  Read the code and
     * you will understand what I am talking about.
     */
    switch (o->eigrp.type)
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
        *buffer.word_ptr++ = htons(o->eigrp.length ? 
            o->eigrp.length : EIGRP_TLEN_PARAMETER);
        *buffer.byte_ptr++ = TEST_BITS(o->eigrp.values, EIGRP_KVALUE_K1) ? 
          __8BIT_RND(o->eigrp.k1) : o->eigrp.k1;
        *buffer.byte_ptr++ = TEST_BITS(o->eigrp.values, EIGRP_KVALUE_K2) ? 
          __8BIT_RND(o->eigrp.k2) : o->eigrp.k2;
        *buffer.byte_ptr++ = TEST_BITS(o->eigrp.values, EIGRP_KVALUE_K3) ? 
          __8BIT_RND(o->eigrp.k3) : o->eigrp.k3;
        *buffer.byte_ptr++ = TEST_BITS(o->eigrp.values, EIGRP_KVALUE_K4) ? 
          __8BIT_RND(o->eigrp.k4) : o->eigrp.k4;
        *buffer.byte_ptr++ = TEST_BITS(o->eigrp.values, EIGRP_KVALUE_K5) ? 
          __8BIT_RND(o->eigrp.k5) : o->eigrp.k5;
        *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
        *buffer.word_ptr++ = htons(o->eigrp.hold);

        offset += EIGRP_TLEN_PARAMETER;

        /* Going to the next TLV, if it needs to do so-> */
        if (o->eigrp.type == EIGRP_TYPE_SOFTWARE ||
            o->eigrp.type == EIGRP_TYPE_MULTICAST)
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
          *buffer.word_ptr++ = htons(o->eigrp.length ? 
              o->eigrp.length : EIGRP_TLEN_SOFTWARE);
          *buffer.byte_ptr++ = __8BIT_RND(o->eigrp.ios_major);
          *buffer.byte_ptr++ = __8BIT_RND(o->eigrp.ios_minor);
          *buffer.byte_ptr++ = __8BIT_RND(o->eigrp.ver_major);
          *buffer.byte_ptr++ = __8BIT_RND(o->eigrp.ver_minor);
          
          offset += EIGRP_TLEN_SOFTWARE;

          /* Going to the next TLV, if it needs to do so-> */
          if (o->eigrp.type == EIGRP_TYPE_MULTICAST)
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
            *buffer.word_ptr++ = htons(o->eigrp.length ? 
                o->eigrp.length : EIGRP_TLEN_SEQUENCE);
            *buffer.byte_ptr++ = sizeof(o->eigrp.address);
            *buffer.inaddr_ptr++ = INADDR_RND(o->eigrp.address);

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
            *buffer.word_ptr++ = htons(o->eigrp.length ? 
                o->eigrp.length : EIGRP_TLEN_MULTICAST);
            *buffer.dword_ptr++ = htonl(__32BIT_RND(o->eigrp.multicast));

            offset += EIGRP_TLEN_MULTICAST + 
              EIGRP_TLEN_SEQUENCE;
          }
        }
    }
  }

  /* Computing the checksum. */
  eigrp->check    = o->bogus_csum ? 
    __16BIT_RND(0) : cksum(eigrp, offset);

  /* GRE Encapsulation takes place. */
  gre_checksum(packet, o, packet_size);

  /* Setting SOCKADDR structure. */
  sin.sin_family      = AF_INET;
  sin.sin_port        = htons(IPPORT_RND(o->dest));
  sin.sin_addr.s_addr = o->ip.daddr;

  /* Sending packet. */
  if (sendto(fd, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr *) &sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
    return 1;

  return 0;
}

/* EIGRP header size calculation */
static size_t eigrp_hdr_len(const uint16_t foo,
    const uint16_t bar, const uint8_t baz, const uint32_t qux)
{
  /* The code starts with size '0' and it accumulates all the required
   * size if the conditionals match. Otherwise, it returns size '0'. */
  size_t size=0;

  /*
   * The Authentication Data TVL must be used only in some cases:
   * 1. IP Internal or External Routes TLV for Update
   * 2. Software Version with Parameter TLVs for Hello
   * 3. Next Multicast Sequence TLV for Hello
   */
  if (qux)
  {
    if (foo == EIGRP_OPCODE_UPDATE  ||
        (foo == EIGRP_OPCODE_HELLO   &&
         (bar == EIGRP_TYPE_MULTICAST ||
          bar == EIGRP_TYPE_SOFTWARE)))
      size += EIGRP_TLEN_AUTH;
  }
  /*
   * AFAIK,   there are differences when building the EIGRP packet for
   * Update, Request, Query and Reply.  Any EIGRP PCAP file I saw does
   * not carry Parameter,  Software Version and/or Multicast Sequence,
   * instead, it carries Authentication Data, IP Internal and External
   * Routes or nothing (depends on the EIGRP Type).
   */
  if (foo == EIGRP_OPCODE_UPDATE   ||
      foo == EIGRP_OPCODE_REQUEST  ||
      foo == EIGRP_OPCODE_QUERY    ||
      foo == EIGRP_OPCODE_REPLY)
  {
    /*
     * For both Internal and External Routes TLV the code must perform
     * an additional step to compute the EIGRP header length,  because 
     * it depends on the the EIGRP Prefix, and it can be 1-4 octets.
     */
    if (bar == EIGRP_TYPE_INTERNAL)
    {
      size += EIGRP_TLEN_INTERNAL;
      size += EIGRP_DADDR_LENGTH(baz);
    }
    else if (bar == EIGRP_TYPE_EXTERNAL)
    {
      size += EIGRP_TLEN_EXTERNAL;
      size += EIGRP_DADDR_LENGTH(baz);
    }
    /*
     * In the other hand, EIGRP Packet for Hello can carry Parameter, 
     * Software Version, Multicast Sequence or nothing (Acknowledge).
     */
  }
  else if (foo == EIGRP_OPCODE_HELLO)
  {
    /*
     * AFAIK,  EIGRP TLVs must follow a predefined sequence in order to
     * be built. I am not sure whether any TLV's precedence will impact
     * in the routers'  processing of  EIGRP Packet,  so I am following 
     * exactly what I saw on live  EIGRP PCAP files.  Read the code and
     * you will understand what I am talking about.
     */
    switch(bar)
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

