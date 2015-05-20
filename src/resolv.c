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

/* IP address and name resolving */
in_addr_t resolv(char *name)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
  /* Hints getaddrinfo() to return only IPv4 compatible addresses. */
  struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_flags = AI_ALL | AI_V4MAPPED },
         *res, *res0 = NULL;
#pragma GCC diagnostic pop

  in_addr_t addr = 0;
  int err;

  assert(name != NULL);

  /* FIX: The "service" is not important here! */
  if ((err = getaddrinfo(name, NULL, &hints, &res0)) != 0)
  {
    if (res0)
      freeaddrinfo(res0);

    error("Error on resolv(). getaddrinfo() reports: %s.", gai_strerror(err));
  }

  // FIX: Traverse the linked list trying to find an
  //      IPv4 address (AF_INET is prioritary!) or an IPv6 mapped to IPv4.

  // FIX: The previous routine (until commit 07bd72777a92530930617ec27327425d72d7b915)
  //      had a nasty memory leak.
  res = res0;
  while (res)
  {
    if (res->ai_family == AF_INET)
    {
      addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
      break;
    }
    else if (res->ai_family == AF_INET6)
    {
      // If an IPv6 v4mapped address was already found,
      // ignore this one. Otherwise gets the 4 IPv4 octects.
      if (!addr)
        addr = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr.s6_addr32[3];
    }

    // Next node!
    res = res->ai_next;
  }

  // Free the linked list.
  if (res0)
    freeaddrinfo(res0);

  return addr;
}

