/* vim: set ts=2 et sw=2 : */
/** @file netio.c */
/*
 *  T50 - Experimental Mixed Packet Injector
 *
 *  Copyright (C) 2010 - 2019 - T50 developers
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

#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <t50_defines.h>
#include <t50_errors.h>
#include <t50_netio.h>
#include <t50_randomizer.h>

/* Maximum number of tries to send the packet. */
#define MAX_SENDTO_RETRYS  10

/* Polling timeout is 1 second. */
#define TIMEOUT 1000

/* Initialized for error condition, just in case! */
static int fd = -1;

/* Used for statistics. */
uint64_t bytes_sent = 0ULL;
uint64_t packets_sent = 0ULL;

//static int wait_for_io ( int );
static void socket_setnonblocking( int );
static void socket_setiphdrincl( int );
static ssize_t socket_send ( int, struct sockaddr_in *, void *, size_t );
#ifdef SO_SNDBUF
  static void socket_setup_sendbuffer ( int );
#endif
#ifdef SO_BROADCAST
  static void socket_setbroadcast( int );
#endif
#ifdef SO_PRIORITY
  static void socket_setpriority( int );
#endif

/**
 * Creates and configure a raw socket.
 */
void create_socket ( void )
{
  /* Setting SOCKET RAW.
     NOTE: Protocol must be IPPROTO_RAW on Linux.
           On FreeBSD, if we use 0 IPPROTO_RAW is assumed by default,
           but on linux will cause an error. */
  if ( ( fd = socket ( AF_INET, SOCK_RAW, IPPROTO_RAW ) ) == -1 )
  {
#ifndef NDEBUG
    fatal_error ( "Cannot open raw socket: \"%s\"", strerror ( errno ) );
#else
    fatal_error ( "Cannot open raw socket" );
#endif
  }

  socket_setnonblocking( fd );
  socket_setiphdrincl( fd );

#ifdef SO_SNDBUF
  socket_setup_sendbuffer ( fd );
#endif

#ifdef SO_BROADCAST
  socket_setbroadcast( fd );
#endif

#ifdef SO_PRIORITY
  socket_setpriority( fd );
#endif
}

/**
 * Tiny routine used to make sure the socket file descriptor is closed.
 */
void close_socket ( void )
{
  /* Close only if the descriptor is valid. */
  if ( fd > 0 )
  {
    close ( fd ); // AS_SAFE!

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
 * @return true (success) or false (error).
 */
int send_packet ( const void * const buffer,
                  size_t size,
                  const config_options_T * const restrict co )
{
  struct sockaddr_in sin =
  {
    .sin_family = AF_INET,
    .sin_port = htons ( IPPORT_RND ( co->dest ) ),
    .sin_addr.s_addr = co->ip.daddr    /* Already in network byte order! */
  };

  assert ( buffer != NULL );
  assert ( size > 0 );
  assert ( co != NULL );

  /* Use socket_send(), below. */
  errno = 0;
  if ( socket_send ( fd, &sin, ( void * ) buffer, size ) == -1 )
  {
    if ( errno == EPERM )
      fatal_error ( "Cannot send packet (Permission!?). Please check your firewall rules (iptables?)." );

    return 0;
  }

  packets_sent++;

  return 1;
}

#ifdef SO_SNDBUF
/* Taken from libdnet by Dug Song. */
void socket_setup_sendbuffer ( int fd )
{
  uint32_t i, n;
  socklen_t len;

  /* Getting SO_SNDBUF. */
  len = sizeof ( n );

  if ( getsockopt ( fd, SOL_SOCKET, SO_SNDBUF, &n, &len ) == -1 )
  {
#ifndef NDEBUG
    fatal_error ( "Cannot get socket buffer: \"%s\"", strerror ( errno ) );
#else
    fatal_error ( "Cannot get socket buffer" );
#endif
  }

  /* Setting the maximum SO_SNDBUF in bytes.
   * 128      =  1 Kib
   * 10485760 = 80 Mib */
  i = n + 128;
  while ( i < 10485760 )
  {
    /* Setting SO_SNDBUF. */
    errno = 0;
    if ( setsockopt ( fd, SOL_SOCKET, SO_SNDBUF, &i, sizeof ( i ) ) == -1 )
    {
      if ( errno == ENOBUFS )
        break;

      fatal_error ( "Cannot set socket buffer" );
    }

    i += 128;
  }
}
#endif /* SO_SNDBUF */

// FIXME: Maybe it is necessary to insert a counter, in case of multiple failures...
static ssize_t socket_send ( int fd, struct sockaddr_in *saddr, void *buffer, size_t size )
{
  ssize_t r;

  /* sendto can set errno to EINTR if a signal interrupts the syscall or
     EAGAIN (or EWOULDBLOCK) if there is no room in the send buffer. */
retry:
  errno = 0;
  r = sendto ( fd, buffer, size, MSG_NOSIGNAL, ( struct sockaddr * ) saddr, sizeof ( struct sockaddr_in ) );

  /* FIXME: Is this really necessary? */
  switch ( errno )
  {
    case EINTR:
    case EAGAIN:
#if EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
      goto retry;
  }

  bytes_sent += size;

  return r;
}

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
in_addr_t resolv ( char *name )
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
  /* FIXME: Hints getaddrinfo() to return only IPv4 compatible addresses. 
            Not sure if it is wise to use AF_UNSPEC here... */
  struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_flags = AI_ALL | AI_V4MAPPED },
  *res, *res0 = NULL;
#pragma GCC diagnostic pop

  in_addr_t addr = 0;
  int err;

  assert ( name != NULL );

  if ( ( err = getaddrinfo ( name, NULL, &hints, &res0 ) ) != 0 )
  {
    if ( res0 )
      freeaddrinfo ( res0 );

    error ( "Error on resolv(). getaddrinfo() reports: %s.", gai_strerror ( err ) );
  }

  /* scan all the list. */
  res = res0;
  while ( res && ! addr )
  {
    switch ( res->ai_family )
    {
      case AF_INET:
        addr = ( ( struct sockaddr_in * ) res->ai_addr )->sin_addr.s_addr;
        break;

      // FIXME: This is probably wrong!
      case AF_INET6:
        addr = ( ( struct sockaddr_in6 * ) res->ai_addr )->sin6_addr.s6_addr32[3];
    }

    res = res->ai_next;
  }

  // Free the linked list.
  freeaddrinfo ( res0 );

  return addr;
}

void socket_setnonblocking( int fd )
{
  int flag;

  /* Try to change the socket mode to NON BLOCKING. */
  if ( ( flag = fcntl ( fd, F_GETFL ) ) == -1 )
  {
#ifndef NDEBUG
    fatal_error ( "Cannot get socket flags: \"%s\"", strerror ( errno ) );
#else
    fatal_error ( "Cannot get socket flags" );
#endif
  }

  if ( fcntl ( fd, F_SETFL, flag | O_NONBLOCK ) == -1 )
  {
#ifndef NDEBUG
    fatal_error ( "Cannot set socket to non-blocking mode: \"%s\"", strerror ( errno ) );
#else
    fatal_error ( "Cannot set socket to non-blocking mode" );
#endif
  }
}

void socket_setiphdrincl( int fd )
{
  /* This is valid for Linux */
  int n = 1;

  /* Setting IP_HDRINCL. */
  /* NOTE: We will provide the IP header, but enabling this option, on linux,
           still makes the kernel calculates the checksum and total_length. */
  if ( setsockopt ( fd, IPPROTO_IP, IP_HDRINCL, &n, sizeof ( n ) ) == -1 )
  {
#ifndef NDEBUG
    fatal_error ( "Cannot set socket options: \"%s\"", strerror ( errno ) );
#else
    fatal_error ( "Cannot set socket options" );
#endif
  }
}

#ifdef SO_BROADCAST
void socket_setbroadcast( int fd )
{
  int n = 1;

  if ( setsockopt ( fd, SOL_SOCKET, SO_BROADCAST, &n, sizeof ( n ) ) == -1 )
  {
#ifndef NDEBUG
    fatal_error ( "Cannot set socket broadcast flag: \"%s\"", strerror ( errno ) );
#else
    fatal_error ( "Cannot set socket broadcast flag" );
#endif
  }
}
#endif

#ifdef SO_PRIORITY
void socket_setpriority( int fd )
{
  int n = 1;

  /* FIXME: Is it a good idea to ajust the socket priority to 1? */
  if ( setsockopt ( fd, SOL_SOCKET, SO_PRIORITY, &n, sizeof ( n ) ) == -1 )
  {
#ifndef NDEBUG
    fatal_error ( "Cannot set socket priority: \"%s\"", strerror ( errno ) );
#else
    fatal_error ( "Cannot set socket priority" );
#endif
  }
}
#endif
