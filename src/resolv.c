/*
 *	T50 - Experimental Mixed Packet Injector
 *
 *	Copyright (C) 2010 - 2011 Nelson Brito <nbrito@sekure.org>
 *	Copyright (C) 2011 - Fernando Mercês <fernando@mentebinaria.com.br>
 *
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <common.h>

/* IP address and name resolving */
in_addr_t resolv(char *name)
{
/*   try this method to follow posix, so i try with getaddinfo()  ;-)*/
    struct addrinfo hints, * res, * res0 = NULL;
    struct sockaddr_in * target = NULL;
    int error;
    
    memset(&hints, 0, sizeof(struct addrinfo));
    
    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = 0;
    error = getaddrinfo(name, "http", &hints, &res0);
    
    if(error)
    {
        if (res0)
            freeaddrinfo(res0);
        puts ("error in resolv.c ,on function getaddrinfo()");
    }
    
    for (res = res0; res; res = res->ai_next)
    {
        target = (struct sockaddr_in *) res->ai_addr;
        /* need condition to look if AF is ipv4 or ipv6 , because sin_addr to ipv4 and sin6_addr to ipv6 */
        if (target)
         return (in_addr_t)&target->sin_addr;  

    }
    
    if (res0)
     freeaddrinfo(res0);	
    
    return 0;
/*	
	in_addr_t ip_addr;
	struct hostent *hostname;
	
  / FIXME: gethostbyname is deprecated by POSIX-1:2008 /
	if((hostname = gethostbyname(host)) == NULL)
	{
		ERROR("error resolving hostname");
		exit(EXIT_FAILURE);
	}

	memcpy(&ip_addr, hostname->h_addr, hostname->h_length);

	return ip_addr;
*/



}
