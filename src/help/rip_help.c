#include <common.h>

void rip_help(void)
{
  printf("RIP Options:\n"
         "    --rip-command NUM         RIPv1/v2 command                 (default 2)\n"
         "    --rip-family NUM          RIPv1/v2 address family          (default %d)\n"
         "    --rip-address ADDR        RIPv1/v2 router address          (default RANDOM)\n"
         "    --rip-metric NUM          RIPv1/v2 router metric           (default RANDOM)\n"
         "    --rip-domain NUM          RIPv2 router domain              (default RANDOM)\n"
         "    --rip-tag NUM             RIPv2 router tag                 (default RANDOM)\n"
         "    --rip-netmask ADDR        RIPv2 router subnet mask         (default RANDOM)\n"
         "    --rip-next-hop ADDR       RIPv2 router next hop            (default RANDOM)\n"
         "    --rip-authentication      RIPv2 authentication included    (default OFF)\n"
         "    --rip-auth-key-id NUM     RIPv2 authentication key ID      (default 1)\n"
         "    --rip-auth-sequence NUM   RIPv2 authentication sequence #  (default RANDOM)\n\n",
         AF_INET);
}
