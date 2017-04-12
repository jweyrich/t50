/* vim: set ts=2 et sw=2 : */
/** @file cidr.c */
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

#include <arpa/inet.h>    // ntohl().
#include <t50_config.h>
#include <t50_defines.h>
#include <t50_cidr.h>
#include <t50_errors.h>

static struct cidr cidr = {0};

/**
 * CIDR configuration tiny C algorithm.
 *
 * This will setup cidr structure with values in host order.
 *
 * @param bits Number of "valid" bits on netmask.
 * @param address IP address from command line (in network order).
 * @return Pointer to cidr structure.
 */
struct cidr *config_cidr(const struct config_options * const __restrict__ co)
{
  /*
   * nbrito -- Thu Dec 23 13:06:39 BRST 2010
   * Here is a description of how to calculate,  correctly,  the number of
   * hosts and IP addresses based on CIDR -- three instructions line.
   *
   * (1) Calculate the 'Network Mask' (two simple operations):
   *  a) Bitwise shift to the left (>>) '0xffffffff' using  CIDR gives the
   *     number of bits to calculate the 'Network Mask'.
   *  b) Bitwise logic NOT (~) to turn off the bits that are on,  and turn
   *     on the bits that are off gives the 'Network Mask'.
   *
   * (2) Calculate the number of  hosts'  IP  addresses  available  to the
   *     current CIDR (two simple operations):
   *  a) Subtract  CIDR from 32 gives the host identifier's (bits) portion
   *     for the IP address.
   *  b) Two raised to  the power (pow(3)) of host identifier (bits) gives
   *     the number of all IP addresses available for the CIDR .
   *     NOTE: Subtracting two from this math skips both 'Network Address'
   *           and 'Broadcast Address'.
   *
   * (3) Calculate initial host IP address (two simple operations):
   *  a) Convert IP address to little-endian ('ntohl()').
   *  b) Bitwise logic AND (&) of host identifier (bits) portion of the IP
   *     address and 'Network Mask' adding one  gives the first IP address
   *     for the CIDR.
   */

  if (co->bits < CIDR_MAXIMUM)
  {
    uint32_t netmask;

    //
    // Calc maximum number of ip addresses based on cidr.
    //
    // These will cause "internal error":
    // 0 bits: 0xfffffffe ok
    // 1 bit : 0x7ffffffe ok
    // ...
    //
    // These will work well:
    // 8 bits : 0x00fffffe ok
    // 16 bits: 0x0000fffe ok
    // 30 bits: 2 ok
    //
    // This will work as if 32 bits.
    // 31 bits: 0
    //
    // hostid == 0 means: use the address as is!
    //
    cidr.hostid = (1U << (32 - co->bits)) - 2U;

    /* XXX Sanitizing the maximum host identifier's IP addresses.
     * XXX Should never reaches here!!! */
    if (cidr.hostid > MAXIMUM_IP_ADDRESSES)
    {
      error("internal error detecded -- please, report.\n"
            "cidr.hostid (%u) > MAXIMUM_IP_ADDRESSES (%u): Probably a specific platform error.",
            cidr.hostid, MAXIMUM_IP_ADDRESSES);

      return NULL;
    }

    netmask = ~(~0U >> co->bits);
    cidr.__1st_addr = (ntohl(co->ip.daddr) & netmask) + 1; // avoid bit 0 = 0.
  }
  else
  {
    cidr.hostid = 0;    // means "no random address".
    cidr.__1st_addr = ntohl(co->ip.daddr);
  }

  return &cidr;
}
