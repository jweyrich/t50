#ifndef __DEBUG_INCLUDED__
#define __DEBUG_INCLUDED__

#ifdef __HAVE_DEBUG__
#define PRINT_PTR_DIFF(pstart,pend) \
  { \
    fprintf(stderr, "%s: %lu bytes buffer usage.\n", __FUNCTION__, (pend-pstart)); \
  }

#define PRINT_CALC_SIZE(s) \
  { \
    fprintf(stderr, "%s: %lu bytes buffer size calculated.\n", __FUNCTION__, s); \
  }

#else
#define PRINT_PTR_DIFF(pstart,pend) 
#endif

#endif
