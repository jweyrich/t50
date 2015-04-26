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
  int error;
  char tmp[46];

  assert(name != NULL);

  hints.ai_family = PF_UNSPEC;
  hints.ai_socktype = 0;

  /* FIX: The "service" is not important here! */
  error = getaddrinfo(name, NULL, &hints, &res0);

  if (error)
  {
    char *stmp;

    if (res0)
      freeaddrinfo(res0);

    /* NOTE: Added proper error reporting. */
    if (asprintf(&stmp, "Error on resolv(). getaddrinfo() reports: %s\n", gai_strerror(error)) == -1)
    {
      perror("Error allocating temporary string.");
      abort();
    }

    ERROR(stmp);
    free(stmp);
  }

  for (res = res0; res; res = res->ai_next)
  {
    target = (struct sockaddr_in *)res->ai_addr;

    /* FIXME: Is this safe? The return type is
       in_addr_t, that is an uint32_t, not an "unsigned __int128" (as ipv6 requires)! */
    if (target)
    {
      switch (res->ai_family)
      {
        case AF_INET:
          inet_ntop(AF_INET,&target->sin_addr,tmp,46);
          return inet_addr(tmp);

        /* FIXME: Is it really necessary? T50 only supports IPv4 until now! */
        case AF_INET6:
          inet_ntop(AF_INET6,&((struct sockaddr_in6 *)target)->sin6_addr,tmp,46);
          return inet_addr(tmp);  /* FIXME: There is a potential problem here! */
      }
    }
  }

  if (res0)
    freeaddrinfo(res0);

  return 0;
}
