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

/* Maximum number of tries to send the packet. */
#define MAX_SENDTO_TRIES  100

#ifdef DUMP_DATA
  extern FILE *fdebug;
#endif

/* Initialized for error condition, just in case! */
static socket_t fd = -1;

/* Socket configuration */
int createSocket(void)
{
	socklen_t len;
	unsigned n = 1, *nptr = &n;

	/* Setting SOCKET RAW. */
	if( (fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1 )
	{
		perror("error opening raw socket");
		return FALSE;
	}

	/* Setting IP_HDRINCL. */
	if( setsockopt(fd, IPPROTO_IP, IP_HDRINCL, nptr, sizeof(n)) == -1 )
	{
		perror("error setting socket options");
		return FALSE;
	}

/* Taken from libdnet by Dug Song. */
#ifdef SO_SNDBUF
	len = sizeof(n);
	/* Getting SO_SNDBUF. */
	if ( getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, &len) == -1 )
	{
		perror("error getting socket buffer");
		return FALSE;
	}

	/* Setting the maximum SO_SNDBUF in bytes.
	 * 128      =  1 kilobit
	 * 10485760 = 10 megabytes */
	for (n += 128; n < 10485760; n += 128)
	{
		/* Setting SO_SNDBUF. */
		if ( setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, len) == -1 )
		{
			if(errno == ENOBUFS)	
				break;

			perror("error setting socket buffer");
			return FALSE;
		}
	}
#endif /* SO_SNDBUF */

#ifdef SO_BROADCAST
	/* Setting SO_BROADCAST. */
	if( setsockopt(fd, SOL_SOCKET, SO_BROADCAST, nptr, sizeof(n)) == -1 )
	{
		perror("error setting socket broadcast");
		return FALSE;
	}
#endif /* SO_BROADCAST */

#ifdef SO_PRIORITY
	if( setsockopt(fd, SOL_SOCKET, SO_PRIORITY, nptr, sizeof(n)) == -1 )
	{
		perror("error setting socket priority");
		return FALSE;
	}
#endif /* SO_PRIORITY */

  return TRUE;
}

void closeSocket(void)
{
  if (fd != -1)
    close(fd);
}

int sendPacket(const void * const buffer, size_t size, const struct config_options * const __restrict__ co)
{
  void *p;
  ssize_t sent;
  int num_tries;

#ifdef DUMP_DATA
  size_t sz = size;
#endif

  struct sockaddr_in sin = { 
    .sin_family = AF_INET, 
    .sin_port = htons(IPPORT_RND(co->dest)), 
    .sin_addr = co->ip.daddr 
  };

  assert(buffer != NULL);
  assert(size > 0);
  assert(co != NULL);

  /* FIX: There is no garantee that sendto() will deliver the entire packet at once.
          So, we try MAX_SENDTO_TRIES times before giving up. */ 
  p = (void *)buffer;
  for (num_tries = MAX_SENDTO_TRIES; size > 0 && num_tries--;) 
  {
    if ((sent = sendto(fd, p, size, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(sin))) == -1)
      break;

    size -= sent;
    p += sent;
  }

  if (errno == EPERM)
  {
    ERROR("Error sending packet (Permission!). Please check your firewall rules (iptables?).");
    return FALSE;
  }

  /* FIX */
  if (num_tries < 0)
  {
    ERROR("Error sending packet (Timeout, tried 100 times!).");
    
#ifdef DUMP_DATA
    fprintf(fdebug, "Error sending %zu bytes of data.\n", sz);
#endif
    return FALSE;
  }
#ifdef DUMP_DATA
  else
    fprintf(fdebug, "Data sent:\n");

  dump_buffer(fdebug, buffer, sz);
#endif

  return TRUE;
}
