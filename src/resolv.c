/* vim: set ts=2 et sw=2 : */
/** @file resolv.c */ 
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

/**
 * IPv4 name resolver using getaddrinfo().
 *
 * Since T50 don't support IPv6 addresses, this routine will
 * try to get only the first IPv6 address mapped to IPv4, if
 * no IPv4 address can be found.
 *
 * @param name The name, as in "www.target.com"...
 * @return IPv4 address found (in network order), or 0 if not found.
 */
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

  /* scan all the list. */
  for (res = res0; res; res = res->ai_next)
  {
    switch (res->ai_family)
    {
      case AF_INET:
        addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
        goto end_loop;
        
      case AF_INET6:
        if (!addr)
          addr = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr.s6_addr32[3];
    }
  }
end_loop:

  // Free the linked list.
  if (res0)
    freeaddrinfo(res0);

  return addr;
}
