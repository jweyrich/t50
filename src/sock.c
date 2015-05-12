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
#include <poll.h>

/* Maximum number of tries to send the packet. */
#define MAX_SENDTO_RETRYS  100

/* Polling timeout is 1 second. */
#define TIMEOUT 1000

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
           but on linux will cause an error. */
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
		error("error setting socket broadcast (\"%s\").", strerror(errno));
		return FALSE;
	}
#endif /* SO_BROADCAST */

#ifdef SO_PRIORITY
  /* FIXME: Is it a good idea to ajust the socket priority to 1? */
	if( setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &n, sizeof(n)) == -1 )
	{
		error("error setting socket priority (\"%s\").", strerror(errno));
		return FALSE;
	}
#endif /* SO_PRIORITY */

  return TRUE;
}

void close_socket(void)
{
  /* Close only if the descriptor is valid. */
  if (fd != -1)
    close(fd);
}

int send_packet(const void * const buffer, 
                size_t size, 
                const struct config_options * const __restrict__ co)
{
  void *p;
  ssize_t sent;
  int num_tries;

// Explicitly disabled warning 'cause this initialization is correct!
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"
  struct sockaddr_in sin = { 
    .sin_family = AF_INET, 
    .sin_port = htons(IPPORT_RND(co->dest)), 
    .sin_addr = co->ip.daddr    /* Already in network byte order! */ 
  };

  struct pollfd pfd = { .fd = fd, .events = POLLOUT };
#pragma GCC diagnostic pop

  int pollret;

  assert(buffer != NULL);
  assert(size > 0);
  assert(co != NULL);

  /* FIX: There is no garantee that sendto() will deliver the entire packet at once.
          So, we try MAX_SENDTO_RETRYS times before giving up. */ 
  p = (void *)buffer;
  for (num_tries = MAX_SENDTO_RETRYS; size > 0 && num_tries--;) 
  {
again:
    errno = 0;
    if ((pollret = poll(&pfd, 1, TIMEOUT)) == -1)
    {
      if (errno == EINTR)
        goto again;
      else
        break;
    }
    
    if (pollret == 0)
      continue;

    if (pfd.revents & POLLOUT)
    {
again2:
      errno = 0;    // errno is set only on error, then we have to reset it here.
      if ((sent = sendto(fd, p, size, MSG_NOSIGNAL, (struct sockaddr *)&sin, sizeof(sin))) == -1)
      {
        if (errno == EINTR)
          goto again2;
        else
          break;
      }

      size -= sent;
      p += sent;
    }
  }

  if (errno == EPERM)
  {
    error("Error sending packet (Permission!). Please check your firewall rules (iptables?).");
    return FALSE;
  }

  /* FIX */
  if (num_tries < 0)
  {
    error("Error sending packet (Timeout, tried 100 times!).");
    return FALSE;
  }

  return TRUE;
}
