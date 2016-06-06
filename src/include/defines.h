/* vim: set ts=2 et sw=2 : */
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

#ifndef __DEFINES_INCLUDED__
#define __DEFINES_INCLUDED__

/* Boolean aliases. */
#define FALSE 0
#define TRUE  (!0)
#define OFF   0
#define ON    (!0)

/**
 * Amount of time, in seconds, to wait for child process termination.
 */
#define WAIT_FOR_CHILD_TIMEOUT  5

/** 
 * Initial packet buffer preallocation size (2 kB).
 *
 * This size should be sufficient for all packets. 
 * MTU usually is 1500 bytes long, over ethernet! 
 */
#define INITIAL_PACKET_SIZE 2048

#define CIDR_MINIMUM 8
#define CIDR_MAXIMUM 32 // fix #7

#define MAXIMUM_IP_ADDRESSES  ((1U << 24) - 1)

/* #define INADDR_ANY 0 */ /* NOTE: Already defined @ linux/in.h */
#define IPPORT_ANY 0

/* Global common protocol definitions used by code */
#define AUTH_TYPE_HMACNUL 0x0000
#define AUTH_TYPE_HMACMD5 0x0002
#define AUTH_TLEN_HMACMD5 16

#define auth_hmac_md5_len(foo) ((foo) ? AUTH_TLEN_HMACMD5 : 0)

/* T50 DEFINITIONS. */
#define IPPROTO_T50        69
#define FIELD_MUST_BE_NULL NULL
#define FIELD_MUST_BE_ZERO 0

/** Macro used to test bitmasks */
#define TEST_BITS(x,bits) ((x) & (bits))

/* Randomizer macros and function */
#define __RND(foo)      (((foo) == 0) ? RANDOM() : (foo))
#define INADDR_RND(foo) __RND((foo))
#define IPPORT_RND(foo) __RND((foo))

/** Used to test if "pid" from fork() is from a child process. */
/* NOTE: fork returns always 0 for the child process. */
#define IS_CHILD_PID(p) (!(p))

/* NOTE: This is, actually, platform independent. These builtin functions
         only tells the compiler to privilege one form of conditional jump
         over another, depending how likely or ulikely the criteria is true
         or false!. No actual hardware hints are emitted. */
#ifndef unlikely 
#define unlikely(c) __builtin_expect(!!(c), 0)
#endif
#ifndef likely
#define likely(c) __builtin_expect(!!(c), 1)
#endif

#endif
