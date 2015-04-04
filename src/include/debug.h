#ifndef __DEBUG_INCLUDED__
#define __DEBUG_INCLUDED__

#include <stdio.h>
#include <stdlib.h>

#ifdef __HAVE_DEBUG__
  #ifdef DUMP_DATA
    void dump_buffer(FILE *, void *, size_t);
    void dump_ip(FILE *, void *);
    void dump_psdhdr(FILE *, void *);
    void dump_tcp(FILE *, void *);
    void dump_udp(FILE *, void *);
    void dump_grehdr(FILE *f, void *);
  #endif
#else
#endif

#endif
