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

#ifndef __EIGRP_H__
#define __EIGRP_H__

#include <stdint.h>

#define IPPROTO_EIGRP   88
#define EIGRPVERSION    2
#define EIGRP_FLAG_INIT 0x00000001
#define EIGRP_FLAG_COND 0x00000002

/* EIGRP Message Opcode */
#define EIGRP_OPCODE_UPDATE   1
#define EIGRP_OPCODE_REQUEST  2
#define EIGRP_OPCODE_QUERY    3
#define EIGRP_OPCODE_REPLY    4
#define EIGRP_OPCODE_HELLO    5
#define EIGRP_OPCODE_IPX_SAP  6

/* EIGRP Message Type/Length/Value */
#define EIGRP_TYPE_PARAMETER  1
#define EIGRP_TYPE_AUTH       2
#define EIGRP_TYPE_SEQUENCE   3
#define EIGRP_TYPE_SOFTWARE   4
#define EIGRP_TYPE_MULTICAST  5
#define EIGRP_TYPE_INTERNAL   0x102
#define EIGRP_TYPE_EXTERNAL   0x103

#define EIGRP_TLEN_PARAMETER   12
#define EIGRP_TLEN_AUTH        40
#define EIGRP_PADDING_BLOCK    12
#define EIGRP_MAXIMUM_KEYID    2147483647
#define EIGRP_TLEN_SEQUENCE    9
#define EIGRP_TLEN_SOFTWARE    8
#define EIGRP_TLEN_MULTICAST   8
#define EIGRP_TLEN_INTERNAL    25
#define EIGRP_TLEN_EXTERNAL    45

#define EIGRP_DADDR_BUILD(foo, bar) \
  ((foo) &= htonl(~(0xffffffff >> (((bar) >> 3) * 8))))

#define EIGRP_DADDR_LENGTH(foo) \
  ((((foo) >> 3) & 3) + ((foo) % 8 ? 1 : 0))

/* EIGRP K Values bitmask */
#define EIGRP_KVALUE_K1   0x01
#define EIGRP_KVALUE_K2   0x02
#define EIGRP_KVALUE_K3   0x04
#define EIGRP_KVALUE_K4   0x08
#define EIGRP_KVALUE_K5   0x10

/**
 * Enhanced Interior Gateway Routing Protocol (EIGRP)
 *
 *      0                   1                   2                   3 3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     -----------------------------------------------------------------
 *     |    Version    |    Opcode     |           Checksum            |
 *     -----------------------------------------------------------------
 *     |                             Flags                             |
 *     -----------------------------------------------------------------
 *     |                        Sequence Number                        |
 *     -----------------------------------------------------------------
 *     |                     Acknowledgment Number                     |
 *     -----------------------------------------------------------------
 *     |                   Autonomous System Number                    |
 *     -----------------------------------------------------------------
 *     |                                                               |
 *     //                  TLV (Type/Length/Value)                    //
 *     |                                                               |
 *     -----------------------------------------------------------------
 *
 * Please,  be advised that there is no deep information about EIGRP,  no
 * other than EIGRP PCAP files public available.  Due to that I have done
 * a deep analysis using live EIGRP PCAP files to build the EIGRP Packet.
 *
 * There are some really good resources, such as:
 *
 * http://www.protocolbase.net/protocols/protocol_EIGRP.php
 * http://packetlife.net/captures/category/cisco-proprietary/
 * http://oreilly.com/catalog/iprouting/chapter/ch04.html
 */
struct eigrp_hdr
{
  uint8_t  version,                /* version                     */
           opcode;                 /* opcode                      */
  uint16_t check;                  /* checksum                    */
  uint32_t flags;                  /* flags                       */
  uint32_t sequence;               /* sequence number             */
  uint32_t acknowledge;            /* acknowledgment sequence #   */
  uint32_t as;                     /* autonomous system           */
  uint8_t  __tlv[0];               /* TLV (Type/Length/Value)     */
};

#endif  /* __EIGRP_H */
