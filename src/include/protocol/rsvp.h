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

#ifndef __RSVP_H__
#define __RSVP_H__

#include <stdint.h>

#define RSVPVERSION 1

/* RSVP Message Type */
#define RSVP_MESSAGE_TYPE_PATH     1
#define RSVP_MESSAGE_TYPE_RESV     2
#define RSVP_MESSAGE_TYPE_PATHERR  3
#define RSVP_MESSAGE_TYPE_RESVERR  4
#define RSVP_MESSAGE_TYPE_PATHTEAR 5
#define RSVP_MESSAGE_TYPE_RESVTEAR 6
#define RSVP_MESSAGE_TYPE_RESVCONF 7
#define RSVP_MESSAGE_TYPE_BUNDLE   12
#define RSVP_MESSAGE_TYPE_ACK      13
#define RSVP_MESSAGE_TYPE_SREFRESH 15
#define RSVP_MESSAGE_TYPE_HELLO    20
#define RSVP_MESSAGE_TYPE_NOTIFY   21

/**
 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
 *
 * 3.1.2 Object Formats
 *
 * Every  object  consists of  one or more 32-bit words with a one-
 * word header, with the following format:
 *
 *            0             1              2             3
 *     +-------------+-------------+-------------+-------------+
 *     |       Length (bytes)      |  Class-Num  |   C-Type    |
 *     +-------------+-------------+-------------+-------------+
 *     |                                                       |
 *     //                  (Object contents)                   //
 *     |                                                       |
 *     +-------------+-------------+-------------+-------------+
 */
#define RSVP_OBJECT_HEADER_LENGTH (sizeof(uint16_t) + (sizeof(uint8_t) * 2))

/* RSVP Object Class */
#define RSVP_OBJECT_SESSION         1
#define RSVP_OBJECT_RESV_HOP        3
#define RSVP_OBJECT_INTEGRITY       4
#define RSVP_OBJECT_TIME_VALUES     5
#define RSVP_OBJECT_ERROR_SPEC      6
#define RSVP_OBJECT_SCOPE           7
#define RSVP_OBJECT_STYLE           8
#define RSVP_OBJECT_FLOWSPEC        9
#define RSVP_OBJECT_FILTER_SPEC     10
#define RSVP_OBJECT_SENDER_TEMPLATE 11
#define RSVP_OBJECT_SENDER_TSPEC    12
#define RSVP_OBJECT_ADSPEC          13
#define RSVP_OBJECT_POLICY_DATA     14
#define RSVP_OBJECT_RESV_CONFIRM    15
#define RSVP_OBJECT_MESSAGE_ID      23
#define RSVP_OBJECT_MESSAGE_ID_ACK  24
#define RSVP_OBJECT_MESSAGE_ID_NACK 25

#define RSVP_LENGTH_SESSION         (RSVP_OBJECT_HEADER_LENGTH + 8)
#define RSVP_LENGTH_RESV_HOP        (RSVP_OBJECT_HEADER_LENGTH + 8)
#define RSVP_LENGTH_INTEGRITY       (RSVP_OBJECT_HEADER_LENGTH + 20)
#define RSVP_LENGTH_TIME_VALUES     (RSVP_OBJECT_HEADER_LENGTH + 4)
#define RSVP_LENGTH_ERROR_SPEC      (RSVP_OBJECT_HEADER_LENGTH + 8)
#define RSVP_LENGTH_SCOPE(foo)      (RSVP_OBJECT_HEADER_LENGTH + ((foo) * sizeof(in_addr_t)))
#define RSVP_LENGTH_STYLE           (RSVP_OBJECT_HEADER_LENGTH + 4)
#define RSVP_LENGTH_FLOWSPEC        (RSVP_OBJECT_HEADER_LENGTH + 32)
#define RSVP_LENGTH_FILTER_SPEC     (RSVP_OBJECT_HEADER_LENGTH + 8)
#define RSVP_LENGTH_SENDER_TEMPLATE (RSVP_OBJECT_HEADER_LENGTH + 8)
#define RSVP_LENGTH_SENDER_TSPEC    (RSVP_OBJECT_HEADER_LENGTH + 8)
#define RSVP_LENGTH_ADSPEC          (RSVP_OBJECT_HEADER_LENGTH + ADSPEC_MESSAGE_HEADER)
#define RSVP_LENGTH_RESV_CONFIRM    (RSVP_OBJECT_HEADER_LENGTH + 4)

/* RSVP TSPEC Class Service */
#define TSPEC_MESSAGE_HEADER        4

#define TSPEC_TRAFFIC_SERVICE       1
#define TSPEC_GUARANTEED_SERVICE    2
#define TSPECT_TOKEN_BUCKET_SERVICE 127
#define TSPEC_TOKEN_BUCKET_LENGTH   24
#define TSPEC_SERVICES(foo) \
  ((((foo) == TSPEC_TRAFFIC_SERVICE) || \
    ((foo) == TSPEC_GUARANTEED_SERVICE)) ? \
   TSPEC_TOKEN_BUCKET_LENGTH : 0)

/* RSVP ADSPEC Class Service */
#define ADSPEC_PARAMETER_SERVICE  1
#define ADSPEC_GUARANTEED_SERVICE 2
#define ADSPEC_CONTROLLED_SERVICE 5

#define ADSPEC_MESSAGE_HEADER       4
#define ADSPEC_SERVDATA_HEADER      4
#define ADSPEC_PARAMETER_DATA       4
#define ADSPEC_PARAMETER_LENGTH     (ADSPEC_MESSAGE_HEADER + ((ADSPEC_SERVDATA_HEADER + ADSPEC_PARAMETER_DATA) * 4))
#define ADSPEC_PARAMETER_ISHOPCNT   4
#define ADSPEC_PARAMETER_BANDWIDTH  6
#define ADSPEC_PARAMETER_LATENCY    8
#define ADSPEC_PARAMETER_COMPMTU    10
#define ADSPEC_GUARANTEED_LENGTH    (ADSPEC_MESSAGE_HEADER + ((ADSPEC_SERVDATA_HEADER + ADSPEC_PARAMETER_DATA) * 4))
#define ADSPEC_CONTROLLED_LENGTH    ADSPEC_MESSAGE_HEADER
#define ADSPEC_SERVICES(foo) \
  (ADSPEC_PARAMETER_LENGTH + \
   ((((foo) == ADSPEC_CONTROLLED_SERVICE) || \
     ((foo) == ADSPEC_GUARANTEED_SERVICE)) ? \
    ADSPEC_GUARANTEED_LENGTH : 0) + \
   (((foo) == ADSPEC_CONTROLLED_SERVICE) ? \
    ADSPEC_CONTROLLED_LENGTH : 0))

/**
 * Resource ReSerVation Protocol (RSVP) (RFC 2205)
 *
 * 3.1.1 Common Header
 *
 *            0             1              2             3
 *     +------+------+-------------+----------------------------
 *     | Vers | Flags|  Msg Type   |       RSVP Checksum       |
 *     +------+------+-------------+---------------------------+
 *     |  Send_TTL   | (Reserved)  |        RSVP Length        |
 *     --------------+-------------+----------------------------
 */
struct rsvp_common_hdr
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
  uint16_t flags: 4,               /* flags                       */
           version: 4,             /* version                     */
           type: 8;                /* message type                */
#elif defined(__BIG_ENDIAN_BITFIELD)
  uint16_t version: 4,             /* version                     */
           flags: 4,               /* flags                       */
           type: 8;                /* message type                */
#else
# error "Adjust your <asm/byteorder.h> defines"
#endif
  uint16_t check;                  /* checksum                    */
  uint8_t  ttl;                    /* time to live                */
  uint8_t  reserved;               /* reserved                    */
  uint16_t length;                 /* message length              */
};

#endif  /* __RSVP_H */
