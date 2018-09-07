/* vim: set ts=2 et sw=2 : */
/** @file randomizer.c */
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


#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <t50_defines.h>
#include <t50_errors.h>
#include <t50_randomizer.h>

/* The Random SEED will be created by SRANDOM */
static uint64_t _seed[2];

/* xorshift128+

   We don't have to worry about the lower bits
   been less random than the upper. */
static uint32_t random_xorshift128plus ( void )
{
  uint64_t s0 = _seed[1];
  uint64_t s1 = _seed[0];
  _seed[0] = s0;

  s1 ^= s1 << 23;
  _seed[1] = s1 ^ s0 ^ ( s1 >> 18 ) ^ ( s0 >> 5 );

  return ( _seed[1] + s0 );
}

// NOTE: Intel specific!
static uint32_t random_rdrand ( void )
{
  uint32_t r;

  __asm__ __volatile__ (
    "1: rdrand %0\n"
    "   jnc 1b"
    : "=a" ( r )
  );

  return r;
}

static void empty_srandom ( void ) {}

static void get_random_seed ( void )
{
  // NOTE: Could use gettimeofday() and use it as seed,
  //       but, this way I'll make sure the seed is random.

  int _fd, r;
  void *p, *endp;

  if ( ( _fd = open ( "/dev/urandom", O_RDONLY ) ) == -1 )
    fatal_error ( "Cannot open /dev/urandom to get initial random seed." );

  /* NOTE: initializes this code "global" _seed var. */
  p = &_seed;
  endp = p + sizeof _seed;

  while ( p < endp )
  {
    if ( ( r = read ( _fd, p, endp - p ) ) == -1 )
      break;

    p += r;
  }

  close ( _fd );

  if ( r == -1 )
    fatal_error ( "Cannot read initial seed from /dev/urandom." );
}

/* The "constructor" below will overide this IF the platform is Intel/AMD and
   if RDRAND is supported. */
void ( *SRANDOM ) ( void ) = get_random_seed;
uint32_t ( *RANDOM ) ( void ) = random_xorshift128plus;

/**
 * Returns the Randomized netmask if foo is 0 or the parameter, otherwise.
 *
 * This routine shouldn't be inlined due to its compliexity.
 *
 * @param foo IPv4 netmask (or 0 if randomized).
 * @return Netmask (randomized or otherwise).
 */
uint32_t NETMASK_RND ( uint32_t foo )
{
  if ( ! foo )
  {
    uint32_t t = RANDOM() & 0x1f;
    /* Here t is something between 0 and 31. */

    /* NOTE: This is faster than 't %= 23'. */
    if ( t > 22 )
      t -= 23;

    /* Here t is something between 0 and 22 */

    /* We need someting between 8 and 30 bits only! */
    foo = htonl ( ~ ( ~0U >> ( t + 8 ) ) );
  }

  return foo;
}

// Intel architecture dependend constructor.
#if defined(__i386) || defined(__x86_64)
#define RDRAND_BIT (1U << 30)

//--- Make sure to use RDRAND instruction if the processor has it.
static void _INIT check_rdrand ( void )
{
  int c;

  __asm__ __volatile__ ( "cpuid" : "=c" ( c ) : "a" ( 1 ) :
#ifdef __i386
                         "ebx", "edx"
#else /* x86_64 */
                         "rbx", "rdx"
#endif
                       );

  if ( c & RDRAND_BIT )
  {
    RANDOM = random_rdrand;
    SRANDOM = empty_srandom;  // RDRAND doesn't need a seed.
  }
}
#endif

