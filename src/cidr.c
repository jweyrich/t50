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

#include <common.h>

static struct cidr cidr = {0, 0};

/* CIDR configuration tiny C algorithm */
struct cidr *config_cidr(uint32_t bits, in_addr_t address)
{
  /* FIXME: Don't need to validate bits. It is already done in getIpAndCidrFromString() function @ config.c */

  /*
   * @nbrito -- Thu Dec 23 13:06:39 BRST 2010
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
  if (bits < CIDR_MAXIMUM)
  {
    uint32_t netmask;

    cidr.hostid = (1U << (32 - bits)) - 2U;

    /* XXX Sanitizing the maximum host identifier's IP addresses.
     * XXX Should never reaches here!!! */
    if (cidr.hostid > MAXIMUM_IP_ADDRESSES)
    {
      error("internal error detecded -- please, report.\n"
            "cidr.hostid (%u) > MAXIMUM_IP_ADDRESSES (%u): Probably a specific platform error",
            cidr.hostid, MAXIMUM_IP_ADDRESSES);

      return NULL;
    }

    netmask = ~(~0U >> bits);
    cidr.__1st_addr = (ntohl(address) & netmask) + 1;
  }
  else
  {
    cidr.hostid = 0;
    cidr.__1st_addr = ntohl(address);
  }

  return &cidr;
}


