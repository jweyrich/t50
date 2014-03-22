#include <common.h>

void icmp_help(void)
{
  printf("ICMP Options:\n"
         "    --icmp-type NUM           ICMP type                        (default %d)\n"
         "    --icmp-code NUM           ICMP code                        (default 0)\n"
         "    --icmp-gateway ADDR       ICMP redirect gateway            (default RANDOM)\n"
         "    --icmp-id NUM             ICMP identification              (default RANDOM)\n"
         "    --icmp-sequence NUM       ICMP sequence #                  (default RANDOM)\n\n",
         ICMP_ECHO);
}
