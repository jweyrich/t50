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
#include <t50_errors.h>
#include <t50_randomizer.h>

/* The Random SEED will be created by SRANDOM */
static uint64_t _seed[2];

/* xorshift128+ 

   We don't have to worry about the lower bits
   been less random than the upper. */
uint32_t RANDOM(void)
{
  uint64_t s0 = _seed[1];
  uint64_t s1 = _seed[0];
  _seed[0] = s0;

  s1 ^= s1 << 23;
  _seed[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);

  return (_seed[1] + s0);
}

/**
 * Gets an random seed from /dev/random.
 *
 * Since this routine is used only once there is no problem using "/dev/random".
 */
void SRANDOM(void)
{
#if defined(__x86_64__) || defined(__i386__)

#define RDRAND_BIT (1U << 30)

  uint32_t cap;

  // Get CPUID features info.
  __asm__ __volatile__ ("cpuid" : "=c" (cap) : "a" (1U)
  :
#ifdef __x86_64__
    "rbx", "rdx"
#else
    "ebx", "edx"
#endif
  );

  // if RDRAND is supported...
  if (cap & RDRAND_BIT)
  {
    // NOTE: Why not use RDRAND as our RNG?
    //       Because RDRAND is slow! I use here
    //       only 'cause SRANDOM() is called once
    //       per process.
    //
    //       XorShift128+ is way faster PRNG...

#ifdef __x86_64__
    __asm__ __volatile__ (
      "1: rdrand %0; jnc 1b;\n"
      "2: rdrand %1; jnc 2b;"
      : "=q" (_seed[0]), "=q" (_seed[1])
      : : "cc"
    );
#else
    __asm__ __volatile__ (
      "1: rdrand %0; jnc 1b;\n"
      "2: rdrand %1; jnc 2b;\n"
      "3: rdrand %2; jnc 3b;\n"
      "4: rdrand %3; jnc 4b;"
      : "=r" (*(uint32_t *)_seed), 
        "=r" (*((uint32_t *)_seed + 1)), 
        "=r" (*((uint32_t *)_seed + 2)), 
        "=r" (*((uint32_t *)_seed + 3)), 
      : : "cc"
    );
#endif
  }
  else
#endif
  {
    int _fd;
    int r;

    if ((_fd = open("/dev/random", O_RDONLY)) == -1)
      fatal_error("Cannot open /dev/random to get initial random seed.");

    /* NOTE: initializes this code "global" _seed var. */
    r = read(_fd, &_seed, sizeof(_seed));

    close(_fd);

    if (r == -1)
      fatal_error("Cannot read initial seed from /dev/random.");
  }
}

/**
 * Returns the Randomized netmask if foo is 0 or the parameter, otherwise.
 *
 * This routine shouldn't be inlined due to its compliexity.
 *
 * @param foo IPv4 netmask (or 0 if randomized).
 * @return Netmask (randomized or otherwise).
 */
uint32_t NETMASK_RND(uint32_t foo)
{
  if (foo == INADDR_ANY)
  {
    uint32_t t = RANDOM() & 0x1f;
    /* Here t is something between 0 and 31. */ 

    /* NOTE: This is faster than 't %= 23'. */
    if (t > 22)
      t -= 23;
    /* Here t is something between 0 and 22 */ 

    /* We need someting between 8 and 30 bits only! */
    foo = ~(~0U >> (t + 8));
  }

  return htonl(foo);
}
