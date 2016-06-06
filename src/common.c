/* vim: set ts=2 et sw=2 : */
/** @file common.h */
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

/* Actual packet buffer. Allocated dynamically. */
void  *packet = NULL;

/* Used by alloc_packet(). */
static size_t current_packet_size = 0;

/* Holds the number of modules. Use get_number_of_registered_modules() funcion to get it. */
static size_t number_of_modules = 0;

/**
 * This is the same as rand(), but fixes the problem the upper bit.
 * RAND_MAX is 31 bits long, not 32! And this value is plataform dependent!
 *
 * @return unsigned int pseudo-random number.
 */
#ifdef _EXPERIMENTAL_
  /* xorshift128+ */

  /* Arbitrary seeds. */
  static uint64_t _seed[2] = { 0x748bd5a53132bUL, 
                               0x41c6e6d32143a1c7UL };
   
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
  /* Linear Congruential Pseudo Random Number Generator. */
  static uint64_t _seed = 0xB16B00B5;  /* An arbitrary "random" initial seed. */
  uint32_t RANDOM(void) 
  { return (_seed = 0x41c64e6dUL * _seed + 12345UL) >> 32; } /* Same parameters as in glibc! */
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

  r = read(_fd, &_seed, 
#ifdef _EXPERIMENTAL_
        2*sizeof(uint64_t)
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

    if (t > 22)
      t = -(23 - t);
    
    /* Rotate between 8 and 30 bits only! */
    foo = ~(~0U >> (t + 8));
  }

  return htonl(foo);
}

/**
 * Preallocates the packet buffer.
 *
 * Since VLAs are "dirty" allocations on stack frame, it's not a problem to use
 * the technique below.
 *
 * The function will reallocate memory only if the buffer isn't big enough to acomodate
 * new_packet_size bytes. 
 *
 * @param size Size of the new 'global' packet buffer.
 */
void alloc_packet(size_t new_packet_size)
{
  void *p;

  /* TEST: Because 0 will free the buffer!!! */
  assert(new_packet_size != 0);

  /* Realloc only ig the new packet size is greater than the old. */
  /* NOTE: Assume the condition is false the majority of time. */
  if (unlikely(new_packet_size > current_packet_size))
  {
    /* Tries to reallocate memory. */
    /* NOTE: Assume realloc will not fail. */
    if (unlikely((p = realloc(packet, new_packet_size)) == NULL))
      fatal_error("Error reallocating packet buffer.");

    /* Only assign a new pointer if successfull */
    packet = p;
    current_packet_size = new_packet_size;
  }
}

/**
 * Get the number of registered modules on modules.c.
 *
 * Scan the list of modules (ONCE!), returning the number of itens found on
 * modules list.
 *
 * @return The number of registered modules.
 */
/* Function prototype moved to modules.h. */
size_t get_number_of_registered_modules(void)
{
  modules_table_t *ptbl;

  /* This garantees that the count will be done
     one time only. */
  if (unlikely(number_of_modules == 0))
    for (ptbl = mod_table; ptbl->func; ptbl++, number_of_modules++);

  return number_of_modules;
}

int *get_module_valid_options_list(int protocol)
{
  modules_table_t *ptbl;

  for (ptbl = mod_table; ptbl->func; ptbl++)
    if (ptbl->protocol_id == protocol)
      return ptbl->valid_options;

  /* Returns NULL if not found. */
  return NULL;
}

/* --- Using vfprintf for flexibility. */
static void verror(char *fmt, va_list args)
{
  char *str;

  /* NOTE: Assume asprintf will not fail. */
  if (unlikely((asprintf(&str, PACKAGE ": %s\n", fmt)) == -1))
  {
    fputs(PACKAGE ": Unknown error (not enough memory?).\n", stderr);
    exit(EXIT_FAILURE);
  }

  vfprintf(stderr, str, args);
  free(str);
}

/**
 * Standard error reporting routine. Non fatal version.
 */
void error(char *fmt, ...)
{
  va_list args;

  va_start(args, fmt);
    verror(fmt, args);
  va_end(args);
}

/**
 * Standard error reporting routine. Fatal Version.
 *
 * This function never returns!
 */
void fatal_error(char *fmt, ...) 
{
  va_list args;

  fputs("\a\n", stderr);  /* BEEP! */
  va_start(args, fmt);
    verror(fmt,args);
  va_end(args);

  /* As expected. exit if a failure. */
  exit(EXIT_FAILURE);
}
