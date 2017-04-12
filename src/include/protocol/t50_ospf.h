/* vim: set ts=2 et sw=2 : */
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

#ifndef __OSPF_H__
#define __OSPF_H__

#include <netinet/in.h>
#include <t50_typedefs.h>

#define IPPROTO_OSPF           89
#define OSPFVERSION            2

/* OSPF Message Type */
#define OSPF_TYPE_HELLO        1
#define OSPF_TYPE_DD           2
#define OSPF_TYPE_LSREQUEST    3
#define OSPF_TYPE_LSUPDATE     4
#define OSPF_TYPE_LSACK        5

#define OSPF_TLEN_HELLO        20
#define OSPF_TLEN_NEIGHBOR(foo) ((foo) * sizeof(in_addr_t))
#define OSPF_TLEN_DD           8
#define OSPF_TLEN_LSREQUEST    12
#define OSPF_TLEN_LSUPDATE     4

/* OSPF HELLO, DD and LSA Option */
#define OSPF_OPTION_TOS       0x01
#define OSPF_OPTION_EXTERNAL  0x02
#define OSPF_OPTION_MULTICAST 0x04
#define OSPF_OPTION_NSSA      0x08
#define OSPF_OPTION_LLS       0x10
#define OSPF_OPTION_DEMAND    0x20
#define OSPF_OPTION_OPAQUE    0x40
#define OSPF_OPTION_DOWN      0x80

/* OSPF DD DB Description */
#define DD_DBDESC_MSLAVE      0x01
#define DD_DBDESC_MORE        0x02
#define DD_DBDESC_INIT        0x04
#define DD_DBDESC_OOBRESYNC   0x08

/* OSPF LSA LS Type */
#define LSA_TYPE_ROUTER        1
#define LSA_TYPE_NETWORK       2
#define LSA_TYPE_SUMMARY_IP    3
#define LSA_TYPE_SUMMARY_AS    4
#define LSA_TYPE_ASBR          5
#define LSA_TYPE_MULTICAST     6
#define LSA_TYPE_NSSA          7
#define LSA_TYPE_OPAQUE_LINK   9
#define LSA_TYPE_OPAQUE_AREA  10
#define LSA_TYPE_OPAQUE_FLOOD 11

#define LSA_TLEN_GENERIC(foo) \
  (sizeof(struct ospf_lsa_hdr) + \
   ((foo) * sizeof(uint32_t)))

#define LSA_TLEN_ROUTER        LSA_TLEN_GENERIC(4)
#define LSA_TLEN_NETWORK       LSA_TLEN_GENERIC(2)
#define LSA_TLEN_SUMMARY       LSA_TLEN_GENERIC(2)
#define LSA_TLEN_ASBR          LSA_TLEN_GENERIC(4)
#define LSA_TLEN_MULTICAST     LSA_TLEN_GENERIC(2)
#define LSA_TLEN_NSSA          LSA_TLEN_ASBR

/* OSPF Router-LSA Flag */
#define ROUTER_FLAG_BORDER     0x01
#define ROUTER_FLAG_EXTERNAL   0x02
#define ROUTER_FLAG_VIRTUAL    0x04
#define ROUTER_FLAG_WILD       0x08
#define ROUTER_FLAG_NSSA_TR    0x10

/* OSPF Router-LSA Link type */
#define LINK_TYPE_PTP          1
#define LINK_TYPE_TRANSIT      2
#define LINK_TYPE_STUB         3
#define LINK_TYPE_VIRTUAL      4

/* OSPF Group-LSA Type */
#define VERTEX_TYPE_ROUTER     1
#define VERTEX_TYPE_NETWORK    2

#define OSPF_TLV_HEADER        sizeof(struct ospf_lls_hdr)

/* OSPF LLS Type/Length/Value */
#define OSPF_TLV_RESERVED      0
#define OSPF_TLV_EXTENDED      1
#define OSPF_TLV_CRYPTO        2

#define OSPF_LEN_EXTENDED      OSPF_TLV_HEADER
#define EXTENDED_OPTIONS_LR    0x00000001
#define EXTENDED_OPTIONS_RS    0x00000002
#define OSPF_LEN_CRYPTO        ( OSPF_TLV_HEADER + AUTH_TLEN_HMACMD5 )

/** Calculating OSPF LLS Type/Length/Value length */
#define ospf_tlv_len(foo, bar, baz) \
  ((((foo) == OSPF_TYPE_HELLO) || \
    ((foo) == OSPF_TYPE_DD)) ? \
   ((bar) ? \
    OSPF_TLV_HEADER * 2 + \
    OSPF_LEN_EXTENDED   + \
    ((baz) ? \
     OSPF_TLV_HEADER + \
     OSPF_LEN_CRYPTO : \
     0) : \
    0) : \
   0)

/**
 * OSPF Version 2 (RFC 2328)
 *
 * A.3.1 The OSPF packet header
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |   Version #   |     Type      |         Packet length         |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                         Router ID                            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                           Area ID                             |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |           Checksum            |             AuType            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ospf_hdr
{
  uint8_t  version,            /* version               */
           type;               /* type                  */
  uint16_t length;             /* length                */
  in_addr_t rid;               /* router ID             */
  in_addr_t aid;               /* area ID               */
  uint16_t check;              /* checksum              */
  uint16_t autype;             /* authentication type   */
  uint8_t  __ospf_auth[0];     /* authentication header */
  uint8_t  __ospf_type_hdr[0]; /* type header           */
};

/**
 * OSPF Version 2 (RFC 2328)
 *
 * A.3.1 The OSPF packet header
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                       Authentication                          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                       Authentication                          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * D.3 Cryptographic authentication
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |              0                |    Key ID     | Auth Data Len |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                 Cryptographic sequence number                 |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ospf_auth_hdr
{
  uint16_t reserved; /* reserved must be zero       */
  uint8_t  key_id,   /* authentication key ID       */
           length;   /* authentication length       */
  uint32_t sequence; /* authentication sequence #   */
};

/**
 * OSPF Version 2 (RFC 2328)
 *
 * A.4.1 The Link State Advertisement (LSA) header
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |            LS age             |    Options    |    LS type    |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                        Link State ID                          |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                     Advertising Router                        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                     LS sequence number                        |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |         LS checksum           |             length            |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ospf_lsa_hdr
{
  uint16_t age;                    /* LSA age                     */
  uint8_t  options;                /* LSA options                 */
  uint8_t  type;                   /* LSA type                    */
  in_addr_t lsid;                   /* LSA link state ID           */
  in_addr_t router;                 /* LSA advertising router      */
  uint32_t sequence;               /* LSA sequence number         */
  uint16_t check;                  /* LSA checksum                */
  uint16_t length;                 /* LSA length                  */
};

/**
 * OSPF Link-Local Signaling (RFC 5613)
 *
 * 2.2.  LLS Data Block
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |            Checksum           |       LLS Data Length         |
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *     |                                                               |
 *     |                           LLS TLVs                            |
 *     .                                                               .
 *     .                                                               .
 *     .                                                               .
 *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
struct ospf_lls_hdr
{
  uint16_t check;                  /* LLS checksum                */
  uint16_t length;                 /* LLS length                  */
};

#endif  /* __OSPF_H */
