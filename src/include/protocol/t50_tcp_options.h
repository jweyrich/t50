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

#ifndef __TCP_OPTIONS_H__
#define __TCP_OPTIONS_H__

#include <stdint.h>

#define TCPOPT_EOL        0
#define TCPOPT_NOP        1
#define TCPOPT_MSS        2
#define TCPOPT_WSOPT      3
#define TCPOPT_SACK_OK    4
#define TCPOPT_SACK_EDGE  5
#define TCPOPT_TSOPT      8
#define TCPOPT_CC         11
#define TCPOPT_CC_NEW     12
#define TCPOPT_CC_ECHO    13
#define TCPOPT_MD5        19
#define TCPOPT_AO         29

#define TCPOLEN_MSS       4
#define TCPOLEN_WSOPT     3
#define TCPOLEN_SACK_OK   2
#define TCPOLEN_CC        6
#define TCPOLEN_TSOPT     10
#define TCPOLEN_MD5       18
#define TCPOLEN_AO        20

/**
 * TCP Selective Acknowledgement Options (SACK) (RFC 2018)
 *
 * A SACK option that specifies n blocks will  have a length of 8*n+2
 * bytes,  so  the  40 bytes  available for TCP options can specify a
 * maximum of 4 blocks.   It is expected that SACK will often be used
 * in conjunction with the Timestamp option used for RTTM,which takes
 * an additional 10 bytes (plus two bytes of padding); thus a maximum
 * of 3 SACK blocks will be allowed in this case.
 */
#define TCPOLEN_SACK_EDGE(foo) (((foo) * (sizeof(uint32_t) * 2)) + TCPOLEN_SACK_OK)

/**
 * Transmission Control Protocol (TCP) (RFC 793)
 *
 * Padding:  variable
 *
 * The TCP header padding is used to ensure that the TCP header ends
 * and data begins on a 32 bit boundary.  The padding is composed of
 * zeros.
 */
#define TCPOLEN_PADDING(foo) (((foo) & 3) ? sizeof(uint32_t) - ((foo) & 3) : 0)

/* TCP Options bitmask. */
#define TCP_OPTION_MSS        0x01
#define TCP_OPTION_WSOPT      0x02
#define TCP_OPTION_TSOPT      0x04
#define TCP_OPTION_SACK_OK    0x08
#define TCP_OPTION_CC         0x10
#define TCP_OPTION_CC_NEXT    0x20
#define TCP_OPTION_SACK_EDGE  0x40

#endif  /* __TCP_OPTIONS_H */
