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
  /* try this method to follow posix, so i try with getaddinfo()  ;-) */
  struct addrinfo hints = {}, *res, *res0 = NULL;
#pragma GCC diagnostic pop

  struct sockaddr_in *target = NULL;
  int err;

#define ADDRSTRLEN INET6_ADDRSTRLEN
#if INET_ADDRSTRLEN > ADDRSTRLEN
  #define ADDRSTRLEN INET_ADDRSTRLEN
#endif

  assert(name != NULL);

  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = 0;

  /* FIX: The "service" is not important here! */
  if ((err = getaddrinfo(name, NULL, &hints, &res0)) != 0)
  {
    if (res0)
      freeaddrinfo(res0);

    error("Error on resolv(). getaddrinfo() reports: %s.", gai_strerror(err));
  }

  for (res = res0; res; res = res->ai_next)
  {
    target = (struct sockaddr_in *)res->ai_addr;

    if (target)
    {
      in_addr_t addr;

      switch (res->ai_family)
      {
        case AF_INET:
          addr = target->sin_addr.s_addr;
          if (res0)
            freeaddrinfo(res0);
          return addr;

        /* FIX: Added support only for IPv6 mapped to IPv4 addresses.
                Returns 0, otherwise. */
        case AF_INET6:
          if (!IN6_IS_ADDR_V4MAPPED(target))
            goto error;          

          addr = (in_addr_t)((struct sockaddr_in6 *)target)->sin6_addr.s6_addr32[3];

          if (res0)
            freeaddrinfo(res0);
          return addr;
      }
    }
  }

error:
  if (res0)
    freeaddrinfo(res0);

  return 0;
}
