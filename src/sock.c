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
#define MAX_SENDTO_RETRYS  100

#ifdef DUMP_DATA
  extern FILE *fdebug;
#endif

/* Initialized for error condition, just in case! */
static socket_t fd = -1;

/* Socket configuration */
int create_socket(void)
{
	socklen_t len;
	unsigned i, n = 1;

	/* Setting SOCKET RAW. 
     NOTE: Protocol must be IPPROTO_RAW on Linux.
           On FreeBSD, if we use 0 IPPROTO_RAW is assumed by default,
           but links will cause an error. */
	if( (fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1 )
	{
		perror("error opening raw socket");
		return FALSE;
	}

	/* Setting IP_HDRINCL. */
  /* NOTE: Enabling this option makes sure that checksum and total_length 
           are calculated by the kernel. */
  /* FIXME: MAYBE disabling this option could be a good thing on
            OS/X. In this case, we MUST calculate the ip's checksum manually. */
	if( setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n)) == -1 )
	{
		perror("error setting socket options");
		return FALSE;
	}

/* Taken from libdnet by Dug Song. */
#ifdef SO_SNDBUF
	/* Getting SO_SNDBUF. */
	len = sizeof(n);
	if ( getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, &len) == -1 )
	{
		perror("error getting socket buffer");
		return FALSE;
	}

	/* Setting the maximum SO_SNDBUF in bytes.
	 * 128      =  1 kbits
	 * 10485760 = 80 Mbits */
	for (i = n + 128; i < 10485760; i += 128)
	{
		/* Setting SO_SNDBUF. */
		if ( setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(unsigned int)) == -1 )
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
  /* NOTE: Enable the ability to send broadcasts. */
	if( setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n)) == -1 )
	{
		perror("error setting socket broadcast");
		return FALSE;
	}
#endif /* SO_BROADCAST */

#ifdef SO_PRIORITY
  /* FIXME: Is it a good idea to ajust the socket priority to 1? */
	if( setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &n, sizeof(n)) == -1 )
	{
		perror("error setting socket priority");
		return FALSE;
	}
#endif /* SO_PRIORITY */

  return TRUE;
}

void close_socket(void)
{
  if (fd != -1)
    close(fd);
}

int send_packet(const void * const buffer, size_t size, const struct config_options * const __restrict__ co)
{
  void *p;
  ssize_t sent;
  int num_tries;

#ifdef DUMP_DATA
  size_t sz = size;
#endif

// Explicitly disabled warning 'cause this initialization is correct!
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"
  struct sockaddr_in sin = { 
    .sin_family = AF_INET, 
    .sin_port = htons(IPPORT_RND(co->dest)), 
    .sin_addr = co->ip.daddr 
  };
#pragma GCC diagnostic pop

  assert(buffer != NULL);
  assert(size > 0);
  assert(co != NULL);

  /* FIX: There is no garantee that sendto() will deliver the entire packet at once.
          So, we try MAX_SENDTO_RETRYS times before giving up. */ 
  p = (void *)buffer;
  for (num_tries = MAX_SENDTO_RETRYS; size > 0 && num_tries--;) 
  {
    errno = 0;    // errno is set only on error, then we have to reset it here.

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
