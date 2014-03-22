#include <common.h>

void igmp_help(void)
{
  printf("IGMP Options:\n"
         "    --igmp-type NUM           IGMPv1/v3 type                   (default 0x%x)\n"
         "    --igmp-code NUM           IGMPv1/v3 code                   (default 0)\n"
         "    --igmp-group ADDR         IGMPv1/v3 address                (default RANDOM)\n"
         "    --igmp-qrv NUM            IGMPv3 QRV                       (default RANDOM)\n"
         "    --igmp-suppress           IGMPv3 suppress router-side      (default OFF)\n"
         "    --igmp-qqic NUM           IGMPv3 QQIC                      (default RANDOM)\n"
         "    --igmp-grec-type NUM      IGMPv3 group record type         (default 1)\n"
         "    --igmp-sources NUM        IGMPv3 # of sources              (default 2)\n"
         "    --igmp-multicast ADDR     IGMPv3 group record multicast    (default RANDOM)\n"
         "    --igmp-address ADDR,...   IGMPv3 source address(es)        (default RANDOM)\n\n",
         IGMP_HOST_MEMBERSHIP_QUERY);
}
