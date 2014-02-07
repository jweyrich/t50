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
static size_t ospf_hdr_len(const uint8_t, const uint8_t, const uint8_t, const uint8_t);

/* Function Name: OSPF packet header configuration.

Description:   This function configures and sends the OSPF packet header.

Targets:       N/A */
int ospf(const socket_t fd, const struct config_options *o)
{
  /* GRE options size. */
  size_t greoptlen = gre_opt_len(o->gre.options, o->encapsulated);

  /* OSPF options? */
  const uint8_t ospf_options = __8BIT_RND(o->ospf.options);

  /* OSPF LLS Header? */
  uint8_t lls = TEST_BITS(ospf_options, OSPF_OPTION_LLS) ? 1 : 0;

  /* OSPF Header length. */
  size_t ospf_length = ospf_hdr_len(o->ospf.type, o->ospf.neighbor, o->ospf.lsa_type, o->ospf.dd_include_lsa);

  /* Packet size. */
  const uint32_t packet_size = sizeof(struct iphdr) + 
    greoptlen                      + 
    sizeof(struct ospf_hdr)        + 
    sizeof(struct ospf_auth_hdr)   + 
    ospf_length                    + 
    auth_hmac_md5_len(o->ospf.auth) + 
    ospf_tlv_len(o->ospf.type, lls, o->ospf.auth);

  /* Checksum offset, GRE offset and Counter. */
  uint32_t offset, counter;

  /* Packet and Checksum. */
  uint8_t *checksum;

  /* Socket address and IP header. */
  struct sockaddr_in sin;
  struct iphdr * ip;

  /* OSPF header. */
  struct ospf_hdr * ospf;

  /*  OSPF Auth header, LSA header and LLS TLVs. */
  struct ospf_auth_hdr * ospf_auth;
  struct ospf_lsa_hdr * ospf_lsa;
  struct ospf_lls_hdr * ospf_lls;

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

  gre_encapsulation(packet, o, 
        sizeof(struct iphdr) + 
        sizeof(struct ospf_hdr)        + 
        sizeof(struct ospf_auth_hdr)   + 
        ospf_length                    + 
        auth_hmac_md5_len(o->ospf.auth) + 
        ospf_tlv_len(o->ospf.type, lls, o->ospf.auth));

  /* OSPF Header structure making a pointer to  IP Header structure. */
  ospf          = (struct ospf_hdr *)((uint8_t *)ip + sizeof(struct iphdr) + greoptlen);
  ospf->version = OSPFVERSION;
  ospf->type    = o->ospf.type;
  /*
   * OSPF Version 2 (RFC 2328)
   *
   * D.3 Cryptographic authentication
   *
   * The message digest appended to  the OSPF packet is not actually
   * considered part of the OSPF protocol packet: the message digest
   * is not included in the OSPF header's packet length, although it
   * is included in the packet's IP header length field.
   */
  ospf->length  = htons(o->ospf.length ? 
      o->ospf.length : 
      sizeof(struct ospf_hdr) + 
      sizeof(struct ospf_auth_hdr)  + 
      ospf_length);
  ospf->rid     = INADDR_RND(o->ospf.rid);
  ospf->aid     = o->ospf.AID ? INADDR_RND(o->ospf.aid) : o->ospf.aid;
  ospf->check   = 0;

  /* OSPF Authentication Header structure making a pointer to OSPF Header structure. */
  ospf_auth       = (struct ospf_auth_hdr *)((uint8_t *)ospf + sizeof(struct ospf_hdr));
  /* Identifiyingt whether to use Authentication or not. */
  if (o->ospf.auth)
  {
    /*
     * OSPF Version 2 (RFC 2328)
     *
     * D.3 Cryptographic authentication
     *
     *   0                   1                   2                   3
     *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |              0                |    Key ID     | Auth Data Len |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |                 Cryptographic sequence number                 |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    ospf->autype        = htons(AUTH_TYPE_HMACMD5);
    ospf_auth->reserved = FIELD_MUST_BE_ZERO;
    ospf_auth->key_id   = __8BIT_RND(o->ospf.key_id);
    ospf_auth->length   = auth_hmac_md5_len(o->ospf.auth);
    ospf_auth->sequence = htonl(__32BIT_RND(o->ospf.sequence));
  }
  else
  {
    /*
     * OSPF Version 2 (RFC 2328)
     *
     * A.3.1 The OSPF packet header
     *
     *   0                   1                   2                   3
     *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |                       Authentication                          |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  |                       Authentication                          |
     *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     */
    ospf->autype        = AUTH_TYPE_HMACNUL;
    ospf_auth->reserved = FIELD_MUST_BE_ZERO;
    ospf_auth->key_id   = FIELD_MUST_BE_ZERO;
    ospf_auth->length   = FIELD_MUST_BE_ZERO;
    ospf_auth->sequence = FIELD_MUST_BE_ZERO;
  }

  /* Computing the Checksum offset. */
  offset = sizeof(struct ospf_auth_hdr);

  /* Storing both Checksum and Packet. */
  checksum = (uint8_t *)ospf_auth + offset;

  /* Identifying the OSPF Type and building it. */
  switch (o->ospf.type)
  {
    case OSPF_TYPE_HELLO:
      /*
       * OSPF Version 2 (RFC 2328)
       *
       * A.3.2 The Hello packet
       *
       *   0                   1                   2                   3
       *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                        Network Mask                           |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |         HelloInterval         |    Options    |    Rtr Pri    |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                     RouterDeadInterval                        |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                      Designated Router                        |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                   Backup Designated Router                    |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                          Neighbor                             |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                              ...                              |
       */
      *((in_addr_t *)checksum) = NETMASK_RND(o->ospf.netmask);
      checksum += sizeof(in_addr_t);
      *((uint16_t *)checksum) = htons(__16BIT_RND(o->ospf.hello_interval));
      checksum += sizeof(uint16_t);
      *checksum++ = ospf_options;
      *checksum++ = __8BIT_RND(o->ospf.hello_priority);
      *((uint32_t *)checksum) = htonl(__32BIT_RND(o->ospf.hello_dead));
      checksum += sizeof(uint32_t);
      *((in_addr_t *)checksum) = INADDR_RND(o->ospf.hello_design);
      checksum += sizeof(in_addr_t);
      *((in_addr_t *)checksum) = INADDR_RND(o->ospf.hello_backup);
      checksum += sizeof(in_addr_t);
      /* Computing the Checksum offset. */
      offset += OSPF_TLEN_HELLO;
      /* Dealing with neighbor address(es). */
      for(counter = 0 ; counter < o->ospf.neighbor ; counter++)
      {
        *((in_addr_t *)checksum) = INADDR_RND(o->ospf.address[counter]);
        checksum += sizeof(in_addr_t);
      }
      /* Computing the Checksum offset. */
      offset += OSPF_TLEN_NEIGHBOR(o->ospf.neighbor);
      break;

    case OSPF_TYPE_DD:
      /*
       * OSPF Version 2 (RFC 2328)
       *
       * A.3.3 The Database Description packet
       *
       *   0                   1                   2                   3
       *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |         Interface MTU         |    Options    |0|0|0|0|0|I|M|MS
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                     DD sequence number                        |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                                                               |
       *  +-                                                             -+
       *  |                                                               |
       *  +-                      An LSA Header                          -+
       *  |                                                               |
       *  +-                                                             -+
       *  |                                                               |
       *  +-                                                             -+
       *  |                                                               |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       */
      *((uint16_t *)checksum) = htons(__16BIT_RND(o->ospf.dd_mtu));
      checksum += sizeof(uint16_t);
      *checksum++ = ospf_options;
      *checksum++ = __3BIT_RND(o->ospf.dd_dbdesc);
      *((uint32_t *)checksum) = htonl(__32BIT_RND(o->ospf.dd_sequence));
      checksum += sizeof(uint32_t);
      /* Computing the Checksum offset. */
      offset += OSPF_TLEN_DD;
      break;

    case OSPF_TYPE_LSREQUEST:
      /*
       * OSPF Version 2 (RFC 2328)
       *
       * A.3.4 The Link State Request packet
       *
       *   0                   1                   2                   3
       *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                          LS type                              |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                       Link State ID                           |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                     Advertising Router                        |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       */
      *((uint32_t *)checksum) = htonl(o->ospf.lsa_type);
      checksum += sizeof(uint32_t);
      *((uint32_t *)checksum) = htonl(__32BIT_RND(o->ospf.lsa_lsid));
      checksum += sizeof(uint32_t);
      *((in_addr_t *)checksum) = INADDR_RND(o->ospf.lsa_router);
      checksum += sizeof(in_addr_t);
      /* Computing the Checksum offset. */
      offset += OSPF_TLEN_LSREQUEST;
      break;

    case OSPF_TYPE_LSUPDATE:
      /*
       * OSPF Version 2 (RFC 2328)
       *
       * A.3.5 The Link State Update packet
       *
       *   0                   1                   2                   3
       *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                            # LSAs                             |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                                                               |
       *  +-                                                            +-+
       *  |                             LSAs                              |
       *  +-                                                            +-+
       *  |                              ...                              |
       */
      *((in_addr_t *)checksum) = htonl(1);
      checksum += sizeof(uint32_t);
      /* Going to the OSPF LSA Header and building it. */
      goto build_ospf_lsa;

      /* Identifying the LSA Type and building it. */
build_ospf_lsupdate:
      if (o->ospf.lsa_type == LSA_TYPE_ROUTER)
      {
        /* Setting the correct OSPF LSA Header length. */
        ospf_lsa->length     = htons(o->ospf.length ? 
            o->ospf.length : 
            LSA_TLEN_ROUTER);
        /*
         * The OSPF Not-So-Stubby Area (NSSA) Option (RFC 3101)
         *
         * Appendix B: Router-LSAs
         *
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |  0  Nt|W|V|E|B|        0      |            # links            |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                          Link ID                              |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                         Link Data                             |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |     Type      |     # TOS     |            metric             |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        *checksum++ = __5BIT_RND(o->ospf.lsa_flags);
        *checksum++ = FIELD_MUST_BE_ZERO; 
        *((uint16_t *)checksum) = htons(1);
        checksum += sizeof(uint16_t);
        *((in_addr_t *)checksum) = INADDR_RND(o->ospf.lsa_link_id);
        checksum += sizeof(in_addr_t);
        *((in_addr_t *)checksum) = NETMASK_RND(o->ospf.lsa_link_data);
        checksum += sizeof(in_addr_t);
        *checksum++ = __8BIT_RND(o->ospf.lsa_link_type);
        *checksum++ = FIELD_MUST_BE_ZERO;
        *((uint16_t *)checksum) = htons(__16BIT_RND(o->ospf.lsa_metric));
        checksum += sizeof(uint16_t);
        /* Computing the Checksum offset. */
        offset += OSPF_TLEN_LSUPDATE;
        offset += LSA_TLEN_ROUTER;
        /* Computing the checksum. */
        ospf_lsa->check      =  o->bogus_csum ? 
          __16BIT_RND(0) : 
          cksum((uint16_t *)ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_ROUTER);
      } 
      else if (o->ospf.lsa_type == LSA_TYPE_NETWORK)
      {
        /* Setting the correct OSPF LSA Header length. */
        ospf_lsa->length     = htons(o->ospf.length ? 
            o->ospf.length : 
            LSA_TLEN_NETWORK);
        /*
         * OSPF Version 2 (RFC 2328)
         *
         * A.4.3 Network-LSAs
         *
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                         Network Mask                          |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                        Attached Router                        |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        *((in_addr_t *)checksum) = NETMASK_RND(o->ospf.netmask);
        checksum += sizeof(in_addr_t);
        *((in_addr_t *)checksum) = INADDR_RND(o->ospf.lsa_attached);
        checksum += sizeof(in_addr_t);
        /* Computing the Checksum offset. */
        offset += OSPF_TLEN_LSUPDATE;
        offset += LSA_TLEN_NETWORK;
        /* Computing the checksum. */
        ospf_lsa->check      =  o->bogus_csum  ? 
          __16BIT_RND(0) : 
          cksum((uint16_t *)ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_NETWORK);
      }
      else if (o->ospf.lsa_type == LSA_TYPE_SUMMARY_IP ||
          o->ospf.lsa_type == LSA_TYPE_SUMMARY_AS)
      {
        /* Setting the correct OSPF LSA Header length. */
        ospf_lsa->length     = htons(o->ospf.length ? 
            o->ospf.length : 
            LSA_TLEN_SUMMARY);
        /*
         * OSPF Version 2 (RFC 2328)
         *
         * A.4.4 Summary-LSAs
         *
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                         Network Mask                          |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |      0        |                  metric                       |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        *((in_addr_t *)checksum) = NETMASK_RND(o->ospf.netmask);
        checksum += sizeof(in_addr_t);
        *checksum++ = FIELD_MUST_BE_ZERO;
        *((uint32_t *)checksum) = htonl(__24BIT_RND(o->ospf.lsa_metric) << 8);
        checksum += sizeof(uint32_t) - 1;
        /* Computing the Checksum offset. */
        offset += OSPF_TLEN_LSUPDATE;
        offset += LSA_TLEN_SUMMARY;
        /* Computing the checksum. */
        ospf_lsa->check      =  o->bogus_csum ? 
          __16BIT_RND(0) : 
          cksum((uint16_t *)ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_SUMMARY);
      }
      else if (o->ospf.lsa_type == LSA_TYPE_ASBR ||
          o->ospf.lsa_type == LSA_TYPE_NSSA)
      {
        /* Setting the correct OSPF LSA Header length. */
        ospf_lsa->length     = htons(o->ospf.length ? 
            o->ospf.length : 
            LSA_TLEN_ASBR);
        /*
         * OSPF Version 2 (RFC 2328)
         *
         * A.4.5 AS-external-LSAs
         *
         * The OSPF NSSA Option (RFC 1587)
         *
         * Appendix A: Type-7 Packet Format
         *
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                         Network Mask                          |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |E|     0       |                  metric                       |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                      Forwarding address                       |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                      External Route Tag                       |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        *((in_addr_t *)checksum) = NETMASK_RND(o->ospf.netmask);
        checksum += sizeof(in_addr_t);
        *checksum++ = (o->ospf.lsa_larger ? 0x80 : 0);
        *((uint32_t *)checksum) = htonl(__24BIT_RND(o->ospf.lsa_metric) << 8);
        checksum += sizeof(uint32_t) - 1;
        *((in_addr_t *)checksum) = INADDR_RND(o->ospf.lsa_forward);
        checksum += sizeof(in_addr_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->ospf.lsa_external));
        checksum += sizeof(uint32_t);
        /* Computing the Checksum offset. */
        offset += OSPF_TLEN_LSUPDATE;
        offset += LSA_TLEN_ASBR;
        /* Computing the checksum. */
        ospf_lsa->check      =  o->bogus_csum ? 
          __16BIT_RND(0) : 
          cksum((uint16_t *)ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_ASBR);
      }
      else if (o->ospf.lsa_type == LSA_TYPE_MULTICAST)
      {
        /* Setting the correct OSPF LSA Header length. */
        ospf_lsa->length     = htons(o->ospf.length ? 
            o->ospf.length : 
            LSA_TLEN_MULTICAST);
        /*
         * Multicast Extensions to OSPF (RFC 1584)
         *
         * A.3 Group-membership-LSA
         *
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                        Vertex type                            |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                         Vertex ID                             |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        *((uint32_t *)checksum) = htonl(__2BIT_RND(o->ospf.vertex_type));
        checksum += sizeof(uint32_t);
        *((in_addr_t *)checksum) = INADDR_RND(o->ospf.vertex_id);
        checksum += sizeof(in_addr_t);
        /* Computing the Checksum offset. */
        offset += OSPF_TLEN_LSUPDATE;
        offset += LSA_TLEN_MULTICAST;
        /* Computing the checksum. */
        ospf_lsa->check      =  o->bogus_csum ? 
          __16BIT_RND(0) : 
          cksum((uint16_t *)ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_MULTICAST);
        /* Building a generic OSPF LSA Header. */
      }
      else
      {
        /* Setting the correct OSPF LSA Header length. */
        ospf_lsa->length     = htons(o->ospf.length ? 
            o->ospf.length : 
            LSA_TLEN_GENERIC(0));
        /* Computing the Checksum offset. */
        offset += OSPF_TLEN_LSUPDATE;
        offset += LSA_TLEN_GENERIC(0);
        /* Computing the checksum. */
        ospf_lsa->check      =  o->bogus_csum ? 
          __16BIT_RND(0) : 
          cksum((uint16_t *)ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_GENERIC(0));
      }
      break;

    case OSPF_TYPE_LSACK:
      /*
       * OSPF Version 2 (RFC 2328)
       *
       * A.3.6 The Link State Acknowledgment packet
       *
       *   0                   1                   2                   3
       *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                                                               |
       *  +-                                                             -+
       *  |                                                               |
       *  +-                         An LSA Header                       -+
       *  |                                                               |
       *  +-                                                             -+
       *  |                                                               |
       *  +-                                                             -+
       *  |                                                               |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       */
      /* Going to the OSPF LSA Header and building it. */
      goto build_ospf_lsa;
  }

  /*
   * OSPF Version 2 (RFC 2328)
   *
   * A.3.3 The Database Description packet
   *
   * The rest of the packet consists of a (possibly partial) list of the
   * link-state database's pieces. Each LSA in the database is described
   * by its LSA header.   The LSA header is documented in Section A.4.1.
   * It contains all  the information required to uniquely identify both
   * the LSA and the LSA's current instance.
   */
  if (o->ospf.type == OSPF_TYPE_DD)
  {
    if (o->ospf.dd_include_lsa)
    {
      /* OSPF LSA Header structure making a pointer to Checksum. */
build_ospf_lsa:   
      ospf_lsa             = (struct ospf_lsa_hdr *)((uint8_t *)checksum);
      ospf_lsa->age        = htons(__16BIT_RND(o->ospf.lsa_age));
      /* Deciding whether age or not. */
      if (o->ospf.lsa_dage)
        ospf_lsa->age        |= 0x80;
      ospf_lsa->type       = o->ospf.lsa_type;
      ospf_lsa->options    = ospf_options;
      ospf_lsa->lsid       = INADDR_RND(o->ospf.lsa_lsid);
      ospf_lsa->router     = INADDR_RND(o->ospf.lsa_router);
      ospf_lsa->sequence   = htonl(__32BIT_RND(o->ospf.lsa_sequence));
      ospf_lsa->check      = 0;
      checksum += sizeof(struct ospf_lsa_hdr);
      /* Returning to the OSPF type LSUpdate and continue builing it. */
      if (o->ospf.type == OSPF_TYPE_LSUPDATE)
        goto build_ospf_lsupdate;
      /*
       * At this point, the code does not need to build the entiry LSA Type
       * Header. It just needs to set the correct OSPF LSA Header length.
       */
      if (o->ospf.lsa_type == LSA_TYPE_ROUTER)
        ospf_lsa->length     = htons(o->ospf.length ? 
            o->ospf.length : 
            LSA_TLEN_ROUTER);
      else if (o->ospf.lsa_type == LSA_TYPE_NETWORK)
        ospf_lsa->length     = htons(o->ospf.length ? 
            o->ospf.length : 
            LSA_TLEN_NETWORK);
      else if (o->ospf.lsa_type == LSA_TYPE_SUMMARY_IP ||
          o->ospf.lsa_type == LSA_TYPE_SUMMARY_AS)
        ospf_lsa->length     = htons(o->ospf.length ? 
            o->ospf.length : 
            LSA_TLEN_SUMMARY);
      else if (o->ospf.lsa_type == LSA_TYPE_ASBR ||
          o->ospf.lsa_type == LSA_TYPE_NSSA)
        ospf_lsa->length     = htons(o->ospf.length ? 
            o->ospf.length : 
            LSA_TLEN_ASBR);
      else if (o->ospf.lsa_type == LSA_TYPE_MULTICAST)
        ospf_lsa->length     = htons(o->ospf.length ? 
            o->ospf.length : 
            LSA_TLEN_MULTICAST);
      else
        ospf_lsa->length     = htons(o->ospf.length ? 
            o->ospf.length : 
            LSA_TLEN_GENERIC(0));
      /* Computing the Checksum offset. */
      offset += LSA_TLEN_GENERIC(0);
      /* Computing the checksum. */
      ospf_lsa->check      =  o->bogus_csum ? 
        __16BIT_RND(0) : 
        cksum((uint16_t *)ospf_lsa, LSA_TLEN_GENERIC(0));
    }
  }

  /*
   * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
   */
  for(counter = 0 ; counter < auth_hmac_md5_len(o->ospf.auth) ; counter++)
    *checksum++ = __8BIT_RND(0);
  /* Computing the Checksum offset. */
  offset += auth_hmac_md5_len(o->ospf.auth);

  /*
   * OSPF Link-Local Signaling (RFC 5613)
   *
   * 2.1.  L-Bit in Options Field
   *
   * The L-bit MUST NOT be set except in Hello and DD packets that contain
   * an LLS block.
   */
  if (o->ospf.type == OSPF_TYPE_HELLO ||
      o->ospf.type == OSPF_TYPE_DD)
  {
    if (lls)
    {
      /* OSPF LLS TLVs structure making a pointer to Checksum. */
      ospf_lls         = (struct ospf_lls_hdr *)((uint8_t *)checksum);
      ospf_lls->length = htons(o->ospf.length ? 
          o->ospf.length : 
          ospf_tlv_len(o->ospf.type, lls, o->ospf.auth)/4);
      ospf_lls->check  = 0;
      checksum += sizeof(struct ospf_lls_hdr);
      /*
       * OSPF Link-Local Signaling (RFC 5613)
       *
       * 2.4.  Extended Options and Flags TLV
       *
       *   0                   1                   2                   3
       *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |             1                 |            4                  |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       *  |                  Extended Options and Flags                   |
       *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       */
      *((uint16_t *)checksum) = htons(OSPF_TLV_EXTENDED);
      checksum += sizeof(uint16_t);
      *((uint16_t *)checksum) = htons(OSPF_LEN_EXTENDED);
      checksum += sizeof(uint16_t);
      *((uint32_t *)checksum) = htonl(o->ospf.lls_options);
      checksum += sizeof(uint32_t);
      /*
       * OSPF Link-Local Signaling (RFC 5613)
       *
       * 2.2.  LLS Data Block
       *
       * Note that if the OSPF packet is cryptographically authenticated, the
       * LLS data block MUST also be cryptographically authenticated.
       */
      if (o->ospf.auth)
      {
        /*
         * OSPF Link-Local Signaling (RFC 5613)
         *
         * 2.5.  Cryptographic Authentication TLV (OSPFv2 ONLY)
         *
         *   0                   1                   2                   3
         *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |              2                |         AuthLen               |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                         Sequence Number                       |
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *  |                                                               |
         *  .                                                               .
         *  .                           AuthData                            .
         *  .                                                               .
         *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *
         * This document defines a special TLV that is used for cryptographic
         * authentication (CA-TLV) of the LLS data block.  This TLV MUST only
         * be included in the LLS block  when cryptographic authentication is
         * enabled on the corresponding interface.
         *
         * The CA-TLV MUST NOT appear more than once in the LLS block.  Also,
         * when present,  this TLV MUST be the last TLV in the LLS block.  If 
         * it appears more than once,  only the first occurrence is processed 
         * and any others MUST be ignored.
         */
        *((uint16_t *)checksum) = htons(OSPF_TLV_CRYPTO);
        checksum += sizeof(uint16_t);
        *((uint16_t *)checksum) = htons(OSPF_LEN_CRYPTO);
        checksum += sizeof(uint16_t);
        *((uint32_t *)checksum) = htonl(__32BIT_RND(o->ospf.sequence));
        checksum += sizeof(uint32_t);
        /*
         * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
         */
        for(counter = 0 ; counter < auth_hmac_md5_len(o->ospf.auth) ; counter++)
          *checksum++ = __8BIT_RND(0);
        /*
         * OSPF Link-Local Signaling (RFC 5613)
         *
         * 2.2.  LLS Data Block
         *
         * Note that if the OSPF packet is cryptographically authenticated, the
         * LLS data block MUST also be cryptographically authenticated. In this
         * case, the regular LLS checksum is not calculated, but is instead set
         * to 0.
         */
      }
      else
      {
        /* Computing the checksum. */
        ospf_lls->check  =  o->bogus_csum ? 
          __16BIT_RND(0) : 
          cksum((uint16_t *)ospf_lls, ospf_tlv_len(o->ospf.type, lls, o->ospf.auth));
      }

      /* Computing the Checksum offset. */
      offset += ospf_tlv_len(o->ospf.type, lls, o->ospf.auth);
    }
  }

  /*
   * OSPF Version 2 (RFC 2328)
   *
   * D.4.3 Generating Cryptographic authentication
   *
   * (2) The checksum field in the standard OSPF header is not
   *     calculated, but is instead set to 0.
   */
  if (!o->ospf.auth)
    /* Computing the checksum. */
    ospf->check   = o->bogus_csum ? 
      __16BIT_RND(0) : 
      cksum((uint16_t *)ospf, sizeof(struct ospf_hdr) + offset);

  gre_checksum(packet, o, packet_size);

  /* Sending packet. */
  if (sendto(fd, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1 && errno != EPERM)
    return 1;

  return 0;
}

/* Function Name: OSPF header size calculation.

Description:   This function calculates the size of OSPF header.

Targets:       N/A */
static size_t ospf_hdr_len(const uint8_t foo, const uint8_t bar, const uint8_t baz, const uint8_t qux)
{
  size_t size;

  /*
   * The code starts with size '0' and it accumulates all the required
   * size if the conditionals match. Otherwise, it returns size '0'.
   */
  size = 0;

  switch (foo)
  {
    /*
     * The size of a HELLO Message Type may vary based on the presence
     * of neighbor address and the number of neighbor address(es).
     */
    case OSPF_TYPE_HELLO:
      size += OSPF_TLEN_HELLO;
      size += OSPF_TLEN_NEIGHBOR(bar);
      break;
      /*
       * The size of a Database Description (DD)  Message Type may vary 
       * based on the presence of a LSA Header,  depending on the case,
       * it may or may not be included.
       */
    case OSPF_TYPE_DD:
      size += OSPF_TLEN_DD;
      size += (qux ? LSA_TLEN_GENERIC(0) : 0);
      break;

    case OSPF_TYPE_LSREQUEST:
      size += OSPF_TLEN_LSREQUEST;
      break;
      /*
       * The size of a LS Update Message Type may vary based on the type
       * of the LSA Header included in the message.
       */
    case OSPF_TYPE_LSUPDATE:
      size += OSPF_TLEN_LSUPDATE;
      if (baz == LSA_TYPE_ROUTER)
        size += LSA_TLEN_ROUTER;
      else if (baz == LSA_TYPE_NETWORK)
        size += LSA_TLEN_NETWORK;
      else if (baz == LSA_TYPE_SUMMARY_IP ||
          baz == LSA_TYPE_SUMMARY_AS)
        size += LSA_TLEN_SUMMARY;
      else if (baz == LSA_TYPE_ASBR)
        size += LSA_TLEN_ASBR;
      else if (baz == LSA_TYPE_MULTICAST)
        size += LSA_TLEN_MULTICAST;
      else if (baz == LSA_TYPE_NSSA)
        size += LSA_TLEN_NSSA;
      else
        size += LSA_TLEN_GENERIC(0);
      break;

    case OSPF_TYPE_LSACK:
      size += LSA_TLEN_GENERIC(0);
      break;
  }

  return size;
}
