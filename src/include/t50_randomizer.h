#ifndef __RANDOMIZER_H__
#define __RANDOMIZER_H__

#include <stdint.h>

#if !defined(__GNUC__) || (__STDC_VERSION__ < 201112)
#error "Need GCC with C11 standard support to compile!"
#endif

/* Randomizer macros and function */
/* NOTE: int8_t, int16_t, int32_t are synonimous of
         char, short and int. */
/* This macro will use htonX functions only if v is !0. */
/* Sometipes, v is a bitfield and NOT compatible with primitive types.
   Because of this, the default selector is necessary! */
/* RANDOM call results have not endianess! */
#define __RND(v) _Generic((v),               \
  _Bool: (!!(v) ? (v) : RANDOM()),           \
  int8_t: (!!(v) ? (v) : RANDOM()),          \
  int16_t: (!!(v) ? htons((v)) : RANDOM()),  \
  int32_t: (!!(v) ? htonl((v)) : RANDOM()),  \
  uint8_t: (!!(v) ? (v) : RANDOM()),         \
  uint16_t: (!!(v) ? htons((v)) : RANDOM()), \
  uint32_t: (!!(v) ? htonl((v)) : RANDOM()), \
  default: (!!(v) ? (v) : RANDOM()))

// FIX: Random IP addresses and PORTS were reversed by __RND macro above.
#define INADDR_RND(v) ((uint32_t)(!!(v) ? (v) : RANDOM()))
#define IPPORT_RND(v) ((uint16_t)(!!(v) ? (v) : RANDOM()))

uint32_t RANDOM(void);
void     SRANDOM(void);
uint32_t NETMASK_RND(uint32_t);

#endif

