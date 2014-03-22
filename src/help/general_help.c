#include <stdio.h>

void general_help(void)
{
	puts("Common Options:\n"
       "    --threshold NUM           Threshold of packets to send     (default 1000)\n"
       "    --flood                   This option supersedes the \'threshold\'\n"
       "    --encapsulated            Encapsulated protocol (GRE)      (default OFF)\n"
       " -B,--bogus-csum              Bogus checksum                   (default OFF)\n"
#ifdef  __HAVE_TURBO__
			"     --turbo                   Extend the performance           (default OFF)\n"
#endif  /* __HAVE_TURBO__ */
      " -v,--version                 Print version and exit \n"
			" -h,--help                    Display this help and exit\n");
}
