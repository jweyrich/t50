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

#ifndef __EGP_H__
#define __EGP_H__

#define EGPVERSION 2

#include <stdint.h>

/* EGP Message Types */
#define EGP_NEIGHBOR_UPDATE_RESP  1
#define EGP_NEIGHBOR_POLL_COMMAND 2
#define EGP_NEIGHBOR_ACQUISITION  3
#define EGP_NEIGHBOR_REACHABILITY 5
#define EGP_NEIGHBOR_ERROR_RESP   8

/* EGP Message Neighbor Acquisition Codes */
#define EGP_ACQ_CODE_REQUEST_CMD  0
#define EGP_ACQ_CODE_CONFIRM_RESP 1
#define EGP_ACQ_CODE_REFUSE_RESP  2
#define EGP_ACQ_CODE_CEASE_CMD    3
#define EGP_ACQ_CODE_CEASE_ACKCMD 4

/* EGP Message Neighbor Acquisition Type */
#define EGP_ACQ_STAT_UNSPECIFIED  0
#define EGP_ACQ_STAT_ACTIVE_MODE  1
#define EGP_ACQ_STAT_PASSIVE_MODE 2
#define EGP_ACQ_STAT_INSUFFICIENT 3
#define EGP_ACQ_STAT_ADM_PROHIBIT 4
#define EGP_ACQ_STAT_GOING_DOWN   5
#define EGP_ACQ_STAT_PARAMETER    6
#define EGP_ACQ_STAT_VIOLATION    7

/**
 * Exterior Gateway Protocol (EGP) Formal Specification (RFC 904)
 *
 * Appendix A.  EGP Message Formats
 *
 * The  formats  for  the  various  EGP messages are described in this
 * section.  All  EGP  messages  include  a ten-octet header of six fields,
 * which may  be followed  by  additional fields depending on message type.
 * The format of the  header is shown below along with a description of its
 * fields.
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     -----------------------------------------------------------------
 *     | EGP Version # |     Type      |     Code      |    Status     |
 *     -----------------------------------------------------------------
 *     |        Checksum               |       Autonomous System #     |
 *     -----------------------------------------------------------------
 *     |        Sequence #             |
 *     ---------------------------------
 *
 * EGP Version #           assigned number identifying the EGP version
 *                         (currently 2)
 *
 * Type                    identifies the message type
 *
 * Code                    identifies the message code (subtype)
 *
 * Status                  contains message-dependent status information
 *
 * Checksum                The EGP checksum  is the 16-bit one's complement
 *                         of the one's  complement sum  of the EGP message
 *                         starting with the EGP version number field. When
 *                         computing the checksum the checksum field itself
 *                         should be zero.
 *
 * Autonomous System #     assigned   number   identifying  the  particular
 *                         autonomous system
 *
 * Sequence #              send state variable (commands) or  receive state
 *                         variable (responses and indications)
 */
struct egp_hdr
{
  uint8_t  version;                /* version                     */
  uint8_t  type;                   /* type                        */
  uint8_t  code;                   /* code                        */
  uint8_t  status;                 /* status                      */
  uint16_t check;                  /* checksum                    */
  uint16_t as;                     /* autonomous system           */
  uint16_t sequence;               /* sequence number             */
  uint8_t  __data[0];              /* data                        */
};

/**
 * Exterior Gateway Protocol (EGP) Formal Specification (RFC 904)
 *
 * A.1.  Neighbor Acquisition Messages
 *
 *      0                   1                   2                   3
 *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *     -----------------------------------------------------------------
 *     | EGP Version # |     Type      |     Code      |    Status     |
 *     -----------------------------------------------------------------
 *     |        Checksum               |       Autonomous System #     |
 *     -----------------------------------------------------------------
 *     |        Sequence #             |          Hello Interval       |
 *     -----------------------------------------------------------------
 *     |        Poll Interval          |
 *     ---------------------------------
 *
 * Note:  the Hello Interval and Poll Interval fields are present  only  in
 * Request and Confirm messages.
 *
 * Type                    3
 *
 * Code                    0       Request command
 *                         1       Confirm response
 *                         2       Refuse response
 *                         3       Cease command
 *                         4       Cease-ack response
 *
 * Status (see below)      0       unspecified
 *                         1       active mode
 *                         2       passive mode
 *                         3       insufficient resources
 *                         4       administratively prohibited
 *                         5       going down
 *                         6       parameter problem
 *                         7       protocol violation
 *
 * Hello Interval          minimum Hello command polling interval (seconds)
 *
 * Poll Interval           minimum Poll command polling interval (seconds)
 */
struct egp_acq_hdr
{
  uint16_t  hello;                  /* hello interval              */
  uint16_t  poll;                   /* poll interval               */
};

#endif  /* __EGP_H */
