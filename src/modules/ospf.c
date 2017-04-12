/* vim: set ts=2 et sw=2 : */
/** @file ospf.c */
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
#include <t50_defines.h>
#include <t50_config.h>
#include <t50_cksum.h>
#include <t50_memalloc.h>
#include <t50_modules.h>
#include <t50_randomizer.h>

static size_t ospf_hdr_len(const uint32_t, const int, const int, const _Bool);

/**
 * OSPF packet header configuration.
 *
 * This function configures and sends the OSPF packet header.
 *
 * @param co Pointer to T50 configuration structure.
 * @param size Pointer to packet size (updated by the function).
 */
void ospf(const struct config_options *const __restrict__ co, size_t *size)
{
  size_t greoptlen,   /* GRE options size. */
         ospf_length, /* OSPF header length. */
         counter,
         stemp;

  uint8_t ospf_options, /* OSPF options? */
          lls;          /* OSPF LLS header? */

  /* Packet and Checksum. */
  memptr_t buffer;

  struct iphdr *ip;
  struct ospf_hdr *ospf;

  /*  OSPF Auth header, LSA header and LLS TLVs. */
  struct ospf_auth_hdr *ospf_auth;
  struct ospf_lsa_hdr *ospf_lsa;
  struct ospf_lls_hdr *ospf_lls;

  assert(co != NULL);

  greoptlen = gre_opt_len(co);
  ospf_options = __RND(co->ospf.options);
  lls = TEST_BITS(ospf_options, OSPF_OPTION_LLS) ? 1 : 0;
  ospf_length = ospf_hdr_len(co->ospf.type, 
                             co->ospf.neighbor, 
                             co->ospf.lsa_type, 
                             co->ospf.dd_include_lsa);

  *size = sizeof(struct iphdr)             +
          sizeof(struct ospf_hdr)          +
          sizeof(struct ospf_auth_hdr)     +
          greoptlen                        +
          ospf_length                      +
          auth_hmac_md5_len(co->ospf.auth) +
          ospf_tlv_len(co->ospf.type, lls, co->ospf.auth);

  /* Try to reallocate packet, if necessary */
  alloc_packet(*size);

  /* IP Header structure making a pointer to Packet. */
  ip = ip_header(packet, *size, co);

  gre_encapsulation(packet, co,
                    sizeof(struct iphdr)           +
                    sizeof(struct ospf_hdr)        +
                    sizeof(struct ospf_auth_hdr)   +
                    ospf_length                    +
                    auth_hmac_md5_len(co->ospf.auth) +
                    ospf_tlv_len(co->ospf.type, lls, co->ospf.auth));

  /* OSPF Header structure making a pointer to  IP Header structure. */
  ospf          = (struct ospf_hdr *)((unsigned char *)(ip + 1) + greoptlen);
  ospf->version = OSPFVERSION;
  ospf->type    = co->ospf.type;

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
  ospf->length  = htons(co->ospf.length ?
                        co->ospf.length :
                        sizeof(struct ospf_hdr)      +
                        sizeof(struct ospf_auth_hdr) +
                        ospf_length);
  ospf->rid     = htonl(INADDR_RND(co->ospf.rid));
  ospf->aid     = htonl(co->ospf.AID ? INADDR_RND(co->ospf.aid) : co->ospf.aid);
  ospf->check   = 0;

  /* OSPF Authentication Header structure making a pointer to OSPF Header structure. */
  ospf_auth       = (struct ospf_auth_hdr *)(ospf + 1);

  /* Identifiyingt whether to use Authentication or not. */
  ospf_auth->reserved = FIELD_MUST_BE_ZERO;
  if (co->ospf.auth)
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
    ospf_auth->key_id   = __RND(co->ospf.key_id);
    ospf_auth->length   = auth_hmac_md5_len(co->ospf.auth);
    ospf_auth->sequence = htonl(__RND(co->ospf.sequence));
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
    ospf->autype        = AUTH_TYPE_HMACNUL;  /* FIXME: Is this 0? */
    ospf_auth->key_id   = FIELD_MUST_BE_ZERO;
    ospf_auth->length   = FIELD_MUST_BE_ZERO;
    ospf_auth->sequence = FIELD_MUST_BE_ZERO;
  }

  buffer.ptr = ospf_auth + 1;

  /* Identifying the OSPF Type and building it. */
  switch (co->ospf.type)
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
    *buffer.inaddr_ptr++ = NETMASK_RND(co->ospf.netmask);
    *buffer.word_ptr++ = htons(__RND(co->ospf.hello_interval));
    *buffer.byte_ptr++ = ospf_options;
    *buffer.byte_ptr++ = __RND(co->ospf.hello_priority);
    *buffer.dword_ptr++ = htonl(__RND(co->ospf.hello_dead));
    *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->ospf.hello_design));
    *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->ospf.hello_backup));

    /* Dealing with neighbor address(es). */
    /* NOTE: Assume co->ospf.neighbor > 0. */
    for (counter = 0; likely(counter < co->ospf.neighbor); counter++)
      *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->ospf.address[counter]));
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
    *buffer.word_ptr++ = htons(__RND(co->ospf.dd_mtu));
    *buffer.byte_ptr++ = ospf_options;
    *buffer.byte_ptr++ = __RND(co->ospf.dd_dbdesc);
    *buffer.dword_ptr++ = htonl(__RND(co->ospf.dd_sequence));
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
    *buffer.dword_ptr++ = htonl(co->ospf.lsa_type);
    *buffer.dword_ptr++ = htonl(__RND(co->ospf.lsa_lsid));
    *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->ospf.lsa_router));
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
    *buffer.inaddr_ptr++ = htonl(1);
    /* Going to the OSPF LSA Header and building it. */
    goto build_ospf_lsa;

    /* Identifying the LSA Type and building it. */
build_ospf_lsupdate:
    if (co->ospf.lsa_type == LSA_TYPE_ROUTER)
    {
      /* Setting the correct OSPF LSA Header length. */
      ospf_lsa->length     = htons(co->ospf.length ?
                                   co->ospf.length :
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
      *buffer.byte_ptr++ = __RND(co->ospf.lsa_flags);
      *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
      *buffer.word_ptr++ = htons(1);
      *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->ospf.lsa_link_id));
      *buffer.inaddr_ptr++ = NETMASK_RND(co->ospf.lsa_link_data);
      *buffer.byte_ptr++ = __RND(co->ospf.lsa_link_type);
      *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
      *buffer.word_ptr++ = htons(__RND(co->ospf.lsa_metric));

      /* Computing the checksum. */
      ospf_lsa->check      =  co->bogus_csum ?
                              RANDOM() :
                              cksum(ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_ROUTER);
    }
    else if (co->ospf.lsa_type == LSA_TYPE_NETWORK)
    {
      /* Setting the correct OSPF LSA Header length. */
      ospf_lsa->length     = htons(co->ospf.length ?
                                   co->ospf.length :
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
      *buffer.inaddr_ptr++ = NETMASK_RND(co->ospf.netmask);
      *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->ospf.lsa_attached));

      /* Computing the checksum. */
      ospf_lsa->check      =  co->bogus_csum  ?
                              RANDOM() :
                              cksum(ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_NETWORK);
    }
    else if (co->ospf.lsa_type == LSA_TYPE_SUMMARY_IP ||
             co->ospf.lsa_type == LSA_TYPE_SUMMARY_AS)
    {
      /* Setting the correct OSPF LSA Header length. */
      ospf_lsa->length     = htons(co->ospf.length ?
                                   co->ospf.length :
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
      *buffer.inaddr_ptr++ = NETMASK_RND(co->ospf.netmask);
      *buffer.byte_ptr++ = FIELD_MUST_BE_ZERO;
      *buffer.dword_ptr++ = htonl(__RND(co->ospf.lsa_metric) << 8);
      buffer.ptr--; /* hack! */

      /* Computing the checksum. */
      ospf_lsa->check =  co->bogus_csum ?
                         RANDOM() :
                         cksum(ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_SUMMARY);
    }
    else if (co->ospf.lsa_type == LSA_TYPE_ASBR ||
             co->ospf.lsa_type == LSA_TYPE_NSSA)
    {
      /* Setting the correct OSPF LSA Header length. */
      ospf_lsa->length     = htons(co->ospf.length ?
                                   co->ospf.length :
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
      *buffer.inaddr_ptr++ = NETMASK_RND(co->ospf.netmask);
      *buffer.byte_ptr++ = (co->ospf.lsa_larger ? 0x80 : 0);
      *buffer.dword_ptr++ = htonl(__RND(co->ospf.lsa_metric) << 8);
      buffer.ptr--;   /* hack! */
      *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->ospf.lsa_forward));
      *buffer.dword_ptr++ = htonl(__RND(co->ospf.lsa_external));

      /* Computing the checksum. */
      ospf_lsa->check      =  co->bogus_csum ?
                              RANDOM() :
                              cksum(ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_ASBR);
    }
    else if (co->ospf.lsa_type == LSA_TYPE_MULTICAST)
    {
      /* Setting the correct OSPF LSA Header length. */
      ospf_lsa->length     = htons(co->ospf.length ?
                                   co->ospf.length :
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
      *buffer.dword_ptr++ = htonl(__RND(co->ospf.vertex_type));
      *buffer.inaddr_ptr++ = htonl(INADDR_RND(co->ospf.vertex_id));

      /* Computing the checksum. */
      ospf_lsa->check      =  co->bogus_csum ?
                              RANDOM() :
                              cksum(ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_MULTICAST);
      /* Building a generic OSPF LSA Header. */
    }
    else
    {
      /* Setting the correct OSPF LSA Header length. */
      ospf_lsa->length     = htons(co->ospf.length ?
                                   co->ospf.length :
                                   LSA_TLEN_GENERIC(0));

      /* Computing the checksum. */
      ospf_lsa->check      =  co->bogus_csum ?
                              RANDOM() :
                              cksum(ospf_lsa, OSPF_TLEN_LSUPDATE + LSA_TLEN_GENERIC(0));
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
  if (co->ospf.type == OSPF_TYPE_DD)
  {
    if (co->ospf.dd_include_lsa)
    {
      /* OSPF LSA Header structure making a pointer to Checksum. */
build_ospf_lsa:
      ospf_lsa             = buffer.ptr;
      ospf_lsa->age        = htons(__RND(co->ospf.lsa_age));

      /* Deciding whether age or not. */
      if (co->ospf.lsa_dage)
        ospf_lsa->age     |= 0x80;

      ospf_lsa->type       = co->ospf.lsa_type;
      ospf_lsa->options    = ospf_options;
      ospf_lsa->lsid       = htonl(INADDR_RND(co->ospf.lsa_lsid));
      ospf_lsa->router     = htonl(INADDR_RND(co->ospf.lsa_router));
      ospf_lsa->sequence   = htonl(__RND(co->ospf.lsa_sequence));
      ospf_lsa->check      = 0;

      buffer.ptr = ospf_lsa + 1;

      /* Returning to the OSPF type LSUpdate and continue builing it. */
      if (co->ospf.type == OSPF_TYPE_LSUPDATE)
        goto build_ospf_lsupdate;

      /*
       * At this point, the code does not need to build the entiry LSA Type
       * Header. It just needs to set the correct OSPF LSA Header length.
       */
      if (co->ospf.lsa_type == LSA_TYPE_ROUTER)
        ospf_lsa->length     = htons(co->ospf.length ?
                                     co->ospf.length :
                                     LSA_TLEN_ROUTER);
      else if (co->ospf.lsa_type == LSA_TYPE_NETWORK)
        ospf_lsa->length     = htons(co->ospf.length ?
                                     co->ospf.length :
                                     LSA_TLEN_NETWORK);
      else if (co->ospf.lsa_type == LSA_TYPE_SUMMARY_IP ||
               co->ospf.lsa_type == LSA_TYPE_SUMMARY_AS)
        ospf_lsa->length     = htons(co->ospf.length ?
                                     co->ospf.length :
                                     LSA_TLEN_SUMMARY);
      else if (co->ospf.lsa_type == LSA_TYPE_ASBR ||
               co->ospf.lsa_type == LSA_TYPE_NSSA)
        ospf_lsa->length     = htons(co->ospf.length ?
                                     co->ospf.length :
                                     LSA_TLEN_ASBR);
      else if (co->ospf.lsa_type == LSA_TYPE_MULTICAST)
        ospf_lsa->length     = htons(co->ospf.length ?
                                     co->ospf.length :
                                     LSA_TLEN_MULTICAST);
      else
        ospf_lsa->length     = htons(co->ospf.length ?
                                     co->ospf.length :
                                     LSA_TLEN_GENERIC(0));

      /* Computing the checksum. */
      ospf_lsa->check      =  co->bogus_csum ?
                              RANDOM() :
                              cksum(ospf_lsa, LSA_TLEN_GENERIC(0));
    }
  }

  /*
   * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
   */
  stemp = auth_hmac_md5_len(co->ospf.auth);
  /* NOTE: Assume stemp > 0. */
  for (counter = 0; likely(counter < stemp); counter++)
    *buffer.byte_ptr++ = RANDOM();

  /*
   * OSPF Link-Local Signaling (RFC 5613)
   *
   * 2.1.  L-Bit in Options Field
   *
   * The L-bit MUST NOT be set except in Hello and DD packets that contain
   * an LLS block.
   */
  if (co->ospf.type == OSPF_TYPE_HELLO ||
      co->ospf.type == OSPF_TYPE_DD)
  {
    if (lls)
    {
      /* OSPF LLS TLVs structure making a pointer to Checksum. */
      ospf_lls         = buffer.ptr;
      ospf_lls->length = htons(co->ospf.length ?
                               co->ospf.length :
                               ospf_tlv_len(co->ospf.type, lls, co->ospf.auth) / 4);
      ospf_lls->check  = 0;

      buffer.ptr = ospf_lls + 1;

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
      *buffer.word_ptr++ = htons(OSPF_TLV_EXTENDED);
      *buffer.word_ptr++ = htons(OSPF_LEN_EXTENDED);
      *buffer.dword_ptr++ = htonl(co->ospf.lls_options);

      /*
       * OSPF Link-Local Signaling (RFC 5613)
       *
       * 2.2.  LLS Data Block
       *
       * Note that if the OSPF packet is cryptographically authenticated, the
       * LLS data block MUST also be cryptographically authenticated.
       */
      if (co->ospf.auth)
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
        *buffer.word_ptr++ = htons(OSPF_TLV_CRYPTO);
        *buffer.word_ptr++ = htons(OSPF_LEN_CRYPTO);
        *buffer.dword_ptr++ = htonl(__RND(co->ospf.sequence));

        /*
         * The Authentication key uses HMAC-MD5 or HMAC-SHA-1 digest.
         */
        stemp = auth_hmac_md5_len(co->ospf.auth);
        /* NOTE: Assume stemp > 0. */
        for (counter = 0; likely(counter < stemp); counter++)
          *buffer.byte_ptr++ = RANDOM();

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
        ospf_lls->check  =  co->bogus_csum ?
                            RANDOM() :
                            cksum(ospf_lls, ospf_tlv_len(co->ospf.type, lls, co->ospf.auth));
      }
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
  if (!co->ospf.auth)
    /* Computing the checksum. */
    ospf->check   = co->bogus_csum ?
                    RANDOM() :
                    cksum(ospf, buffer.ptr - (void *)ospf);

  gre_checksum(packet, co, *size);
}

/* OSPF header size calculation. */
size_t ospf_hdr_len(const uint32_t type, 
                    const int neighbor, 
                    const int lsa_type, 
                    const _Bool dd_include_lsa)
{
  size_t size;

  /*
   * The code starts with size '0' and it accumulates all the required
   * size if the conditionals match. Otherwise, it returns size '0'.
   */
  size = 0;

  switch (type)
  {
  /*
   * The size of a HELLO Message Type may vary based on the presence
   * of neighbor address and the number of neighbor address(es).
   */
  case OSPF_TYPE_HELLO:
    size += OSPF_TLEN_HELLO +
            OSPF_TLEN_NEIGHBOR(neighbor);
    break;

  /*
   * The size of a Database Description (DD)  Message Type may vary
   * based on the presence of a LSA Header,  depending on the case,
   * it may or may not be included.
   */
  case OSPF_TYPE_DD:
    size += OSPF_TLEN_DD;
    if (dd_include_lsa)
      size += LSA_TLEN_GENERIC(0);
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

    switch (lsa_type)
    {
    case LSA_TYPE_ROUTER:
      size += LSA_TLEN_ROUTER;
      break;

    case LSA_TYPE_NETWORK:
      size += LSA_TLEN_NETWORK;
      break;

    case LSA_TYPE_SUMMARY_IP:
    case LSA_TYPE_SUMMARY_AS:
      size += LSA_TLEN_SUMMARY;
      break;

    case LSA_TYPE_ASBR:
      size += LSA_TLEN_ASBR;
      break;

    case LSA_TYPE_MULTICAST:
      size += LSA_TLEN_MULTICAST;
      break;

    case LSA_TYPE_NSSA:
      size += LSA_TLEN_NSSA;
      break;

    default:
      size += LSA_TLEN_GENERIC(0);
    }
    break;

  case OSPF_TYPE_LSACK:
    size += LSA_TLEN_GENERIC(0);
    break;
  }

  return size;
}
