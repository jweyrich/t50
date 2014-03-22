#include <common.h>

void ip_help(void)
{
  printf("IP Options:\n"
       	 " -s,--saddr ADDR              IP source IP address             (default RANDOM)\n"
       	 "    --tos NUM                 IP type of service               (default 0x%x)\n"
       	 "    --id NUM                  IP identification                (default RANDOM)\n"
       	 "    --frag-offset NUM         IP fragmentation offset          (default 0)\n"
       	 "    --ttl NUM                 IP time to live                  (default 255)\n"
       	 "    --protocol PROTO          IP protocol                      (default TCP)\n\n",
         IPTOS_PREC_IMMEDIATE);
}
