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

#ifdef _EXPERIMENTAL_

  /* Arbitrary seeds. */
  static uint64_t _seed[2] = { 0x748bd5a53132bUL, 0x41c6e6d32143a1c7UL };

  /* xorshift128+ */
  uint32_t RANDOM(void)
  {
    uint64_t s0 = _seed[1];
    uint64_t s1 = _seed[0];
    _seed[0] = s0;

    s1 ^= s1 << 23;
    _seed[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);

    return (_seed[1] + s0) >> 32;
  }
#else
  static uint64_t _seed = 0xB16B00B5;  /* An arbitrary "random" initial seed. */

  /** Linear Congruential Pseudo Random Number Generator.
   *
   *  This is the same as rand(), but fixes the problem the upper bit.
   *  RAND_MAX is 31 bits long, not 32! And this value is plataform dependent!
   *
   *  @return uint32_t pseudo-random number.
   */
  uint32_t RANDOM(void)
  {
    // Note _seed is a 64 bit unsigned integer!
    return (_seed = 0x41c64e6dUL * _seed + 12345UL) >> 32;  /* Same parameters as in glibc! */
  }
#endif

/**
 * Gets an random seed from /dev/random.
 *
 * Since this routine is used only once there is no problem using "/dev/random".
 */
void SRANDOM(void)
{
  int _fd;
  int r;

  if ((_fd = open("/dev/random", O_RDONLY)) == -1)
    fatal_error("Cannot open /dev/random to get initial random seed.");

  /* NOTE: initializes this code "global" _seed var. */
  r = read(_fd, &_seed,
#ifdef _EXPERIMENTAL_
           2*sizeof(uint64_t)   // xorshift128 has a 128bit seed!
#else
           sizeof(uint64_t)
#endif
      );

  close(_fd);

  if (r == -1)
    fatal_error("Cannot read initial seed from /dev/random.");
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
    uint32_t t = RANDOM() >> 27; /* Upper 5 bits are more random! */
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
