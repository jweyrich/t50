/* vim: set ts=2 et sw=2 : */
/** @file sock.c */
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

/**
 * Creates and configure a raw socket.
 */
void create_socket(void)
{
  socklen_t len;
  unsigned i, n = 1;  /* FIXME: if I indended, someday, to port
                                this code to Solaris, I must use
                                char to n and set to '1'. 

                                Must change setsockopt() calls as well. */
  int flag;

  /* Setting SOCKET RAW.
     NOTE: Protocol must be IPPROTO_RAW on Linux.
           On FreeBSD, if we use 0 IPPROTO_RAW is assumed by default,
           but on linux will cause an error. */
  if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
  {
    #ifdef __HAVE_DEBUG__
    fatal_error("Error opening raw socket: \"%s\"", strerror(errno));
    #else
    fatal_error("Error opening raw socket");
    #endif
  }

  /* Try to change the socket mode to NON BLOCKING. */
  if ((flag = fcntl(fd, F_GETFL)) == -1)
  {
    #ifdef __HAVE_DEBUG__
    fatal_error("Error getting socket flags: \"%s\"", strerror(errno));
    #else
    fatal_error("Error getting socket flags");
    #endif
  }

  if (fcntl(fd, F_SETFL, flag | O_NONBLOCK) == -1)
  {
    #ifdef __HAVE_DEBUG__
    fatal_error("Error setting socket to non-blocking mode: \"%s\"", strerror(errno));
    #else
    fatal_error("Error setting socket to non-blocking mode");
    #endif
  }

  /* Setting IP_HDRINCL. */
  /* NOTE: We will provide the IP header, but enabling this option, on linux,
           still makes the kernel calculates the checksum and total_length. */
  if ( setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof(n)) == -1 )
  {
    #ifdef __HAVE_DEBUG__
    fatal_error("Error setting socket options: \"%s\"", strerror(errno));
    #else
    fatal_error("Error setting socket options");
    #endif
  }

  /* Taken from libdnet by Dug Song. */
#ifdef SO_SNDBUF
  /* Getting SO_SNDBUF. */
  len = sizeof(n);

  if ( getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &n, &len) == -1 )
  {
    #ifdef __HAVE_DEBUG__
    fatal_error("Error getting socket buffer: \"%s\"", strerror(errno));
    #else
    fatal_error("Error getting socket buffer");
    #endif
  }

  /* Setting the maximum SO_SNDBUF in bytes.
   * 128      =  1 Kib
   * 10485760 = 80 Mib */
  for (i = n + 128; i < 10485760; i += 128)
  {
    /* Setting SO_SNDBUF. */
    if ( setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof(unsigned int)) == -1 )
    {
      if (errno == ENOBUFS)
        break;

      #ifdef __HAVE_DEBUG__
      fatal_error("Error setting socket buffer: \"%s\"", strerror(errno));
      #else
      fatal_error("Error setting socket buffer");
      #endif
    }
  }
#endif /* SO_SNDBUF */

#ifdef SO_BROADCAST
  if ( setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof(n)) == -1 )
  {
    #ifdef __HAVE_DEBUG__
    fatal_error("error setting socket broadcast flag: \"%s\"", strerror(errno));
    #else
    fatal_error("error setting socket broadcast flag");
    #endif
  }
#endif /* SO_BROADCAST */

#ifdef SO_PRIORITY
  /* FIXME: Is it a good idea to ajust the socket priority to 1? */
  if ( setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &n, sizeof(n)) == -1 )
  {
    #ifdef __HAVE_DEBUG__
    fatal_error("error setting socket priority: \"%s\"", strerror(errno));
    #else
    fatal_error("error setting socket priority");
    #endif
  }
#endif /* SO_PRIORITY */
}

/**
 * Tiny routine used to make sure the socket file descriptor is closed.
 */
void close_socket(void)
{
  /* Close only if the descriptor is valid. */
  if (fd > 0)
  {
    close(fd);

    /* Added to avoid multiple socket closing. */
    fd = -1;
  }
}

/**
 * Send a packet through the wire.
 *
 * @param buffer Pointer to the packet buffer.
 * @param size Size of the buffer.
 * @param co Pointer to configurations for T50.
 * @return TRUE (success) or FALSE (error).
 */
int send_packet(const void *const buffer,
                size_t size,
                const struct config_options *const __restrict__ co)
{
  struct sockaddr_in sin =
  {
    .sin_family = AF_INET,
    .sin_port = htons(IPPORT_RND(co->dest)),
    /* FIX: s_addr member was missing! */
    .sin_addr.s_addr = co->ip.daddr    /* Already in network byte order! */
  };

  assert(buffer != NULL);
  assert(size > 0);
  assert(co != NULL);

  /* Use socket_send(), below. */
  /* NOTE: Assume socket_send will not fail. */
  if (unlikely(socket_send(fd, &sin, (void *)buffer, size) == -1))
  {
    if (errno == EPERM)
      fatal_error("Error sending packet (Permission!). Please check your firewall rules (iptables?).");

    return FALSE;
  }

  return TRUE;
}

/*** I realize that EINTR probably never happens, since the signals
     are marked as SA_RESTART, but I want to be sure! */

/* NOTE: Code inspired on Apache httpd source. */
static int wait_for_io(int fd)
{
  int r;
  struct pollfd pfd = { .fd = fd, .events = POLLOUT };

  /* NOTE: Assume poll will not fail. */
  do {
    r = poll(&pfd, 1, TIMEOUT);
  } while (unlikely(r == -1 && errno == EINTR));

  return r;
}

/* NOTE: Code inspired on Apache httpd source. */
static int socket_send(int fd, struct sockaddr_in *saddr, void *buffer, size_t size)
{
  int r;

  /* Tries to send the packet until it's signal interrupted. */
  /* NOTE: Assume sendto will not fail. */
  do { 
    r = sendto(fd, buffer, size, MSG_NOSIGNAL, saddr, sizeof(struct sockaddr_in));
  } while (unlikely(r == -1 && errno == EINTR));

  /* If it wasn't interrupted, tries to send the packet again. */
  /* NOTE: Assume previous sendto will not fail. */
  while (unlikely(r == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)))
  {
    do {
      if ((r = wait_for_io(fd)) == -1)
        goto socket_send_exit;
    } while (unlikely(!r));

    /* ... and tries to send again. */
    do {
      r = sendto(fd, buffer, size, MSG_NOSIGNAL, saddr, sizeof(struct sockaddr_in));
    } while (unlikely(r == -1 && errno == EINTR));
  }

socket_send_exit:
  return r;
}
