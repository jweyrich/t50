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

#include <common.h>

/* IP address and name resolving */
in_addr_t resolv(char *name)
{
/*   try this method to follow posix, so i try with getaddinfo()  ;-)*/
    struct addrinfo hints, * res, * res0 = NULL;
    struct sockaddr_in * target = NULL;
    char tmp[46];
    int error;
    
    memset(&hints, 0, sizeof(struct addrinfo));
    
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = 0;
    error = getaddrinfo(name, "http", &hints, &res0);
    
    if (error)
    {
        if (res0)
            freeaddrinfo(res0);

        /* NOTE: Added proper error reporting. */
        fprintf(stderr, "Error resolv.c. getaddrinfo() error: %s\n", gai_strerror(error));
    }
    
    for (res = res0; res; res = res->ai_next)
    {
      target = (struct sockaddr_in *) res->ai_addr;

			/* FIXME: Is this safe? The return type is
                in_addr_t, that is an uint32_t, not an "unsigned __int128" (as ipv6 requires)! */
      if (target)
      {
         switch (res->ai_family)
         {
          case AF_INET:
            inet_ntop(AF_INET,&target->sin_addr,tmp,46);
            return inet_addr(tmp);
            
          // portable to IPV6
          case AF_INET6:
          // cast struct to ipv6
            inet_ntop(AF_INET6,&((struct sockaddr_in6 *)target)->sin6_addr,tmp,46);
            return inet_addr(tmp);
         
         }  
      }
    }
    
    if (res0)
      freeaddrinfo(res0);	
    
    return 0;
}
