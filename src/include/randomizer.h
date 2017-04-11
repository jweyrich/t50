#ifndef __RANDOMIZER_H__
#define __RANDOMIZER_H__

#include <stdint.h>

/* Randomizer macros and function */
#define __RND(foo)      (((foo) == 0) ? RANDOM() : (foo))
#define INADDR_RND(foo) __RND((foo))
#define IPPORT_RND(foo) __RND((foo))

uint32_t RANDOM(void);
void     SRANDOM(void);
uint32_t NETMASK_RND(uint32_t);

#endif

