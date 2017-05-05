/* Will call RANDOM() only if there is no bits left on __rnd! */

#define RNDSIZE (sizeof(unsigned long)*8)
#define UCHARSIZE (sizeof(unsigned char)*8)
#define USHORTSIZE (sizeof(unsigned short)*8)
#define UINTSIZE (sizeof(unsigned int)*8)

static int __bits_remaining = 0;
static unsigned long __rnd;

extern unsigned long RANDOM(void);

unsigned char BRND(void)
{
  unsigned char r;

  if (__bits_remaining < UCHARSIZE)
  {
    __rnd = RANDOM();
    __bits_remaining = RNDSIZE;    
  }

  r = __rnd;
  __bits_remaining -= UCHARSIZE;
  __rnd >>= UCHARSIZE;

  return r;
}

unsigned short WRND(void)
{
  unsigned short r;

  if (__bits_remaining < USHORTSIZE)
  {
    __rnd = RANDOM();
    __bits_remaining = RNDSIZE;
  }

  r = __rnd;
  __bits_remaining -= USHORTSIZE;
  __rnd >>= USHORTSIZE;

  return r;
}

unsigned int LRND(void)
{
  unsigned int r;

  if (__bits_remaining < UINTSIZE)
  {
    __rnd = RANDOM();
    __bits_remaining = RNDSIZE;
  }

  r = __rnd;
  __bits_remaining -= UINTSIZE;
  __rnd >>= UINTSIZE;

  return r;
}

