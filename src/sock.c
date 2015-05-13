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
#define MAX_SENDTO_RETRYS  10

/* Polling timeout is 1 second. */
#define TIMEOUT 1000

/* Initialized for error condition, just in case! */
static socket_t fd = -1;

static int wait_for_io(int);
static int socket_send(int, struct sockaddr_in *, void *, size_t);

/* Socket configuration */
int create_socket(void)
{
	socklen_t len;
	unsigned i, n = 1;
  int flag;

	/* Setting SOCKET RAW. 
     NOTE: Protocol must be IPPROTO_RAW on Linux.
           On FreeBSD, if we use 0 IPPROTO_RAW is assumed by default,
           but on linux will cause an error. */
	if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		perror("Error opening raw socket");
		return FALSE;
	}

  /* Try to change the socket mode to NON BLOCKING. */
  if ((flag = fcntl(fd, F_GETFL)) == -1)
  {
    perror("Error getting socket flags");
    return FALSE;
  }
  if (fcntl(fd, F_SETFL, flag | O_NONBLOCK) == -1)
  {
    perror("Error setting socket to non-blocking mode");
    return FALSE;
  }

	/* Setting IP_HDRINCL. */
  /* NOTE: We will provide the IP header, but enabling this option, on linux, 
           still makes the kernel calculates the checksum and total_length. */
	if( setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n)) == -1 )
	{
		perror("Error setting socket options");
		return FALSE;
	}

/* Taken from libdnet by Dug Song. */
#ifdef SO_SNDBUF
	/* Getting SO_SNDBUF. */
	len = sizeof(n);
	if ( getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, &len) == -1 )
	{
		perror("Error getting socket buffer");
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

			perror("Error setting socket buffer");
			return FALSE;
		}
	}
#endif /* SO_SNDBUF */

#ifdef SO_BROADCAST
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
// Explicitly disabled warning 'cause this initialization is correct!
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"
  struct sockaddr_in sin = { 
    .sin_family = AF_INET, 
    .sin_port = htons(IPPORT_RND(co->dest)), 
    .sin_addr = co->ip.daddr    /* Already in network byte order! */ 
  };
#pragma GCC diagnostic pop

  assert(buffer != NULL);
  assert(size > 0);
  assert(co != NULL);

  if (socket_send(fd, &sin, (void *)buffer, size) == -1)
  {
    if (errno == EPERM)
      error("Error sending packet (Permission!). Please check your firewall rules (iptables?).");
    return FALSE;
  }

  return TRUE;
}

static int wait_for_io(int fd)
{
  int r;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-braces"
  struct pollfd pfd = { .fd = fd, .events = POLLOUT };
#pragma GCC diagnostic pop

  do {
    r = poll(&pfd, 1, TIMEOUT);
  } while (r == -1 && errno == EINTR);

  return r;
}

static int socket_send(int fd, struct sockaddr_in *saddr, void *buffer, size_t size)
{
  int r;

  do {
    r = sendto(fd, buffer, size, MSG_NOSIGNAL, saddr, sizeof(struct sockaddr_in));
  } while (r == -1 && errno == EINTR);

  while (r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
  {
    if ((r = wait_for_io(fd)) <= 0)
      break;

    do {
      r = sendto(fd, buffer, size, MSG_NOSIGNAL, saddr, sizeof(struct sockaddr_in));
    } while (r == -1 && errno == EINTR);
  }

  return r;
}

