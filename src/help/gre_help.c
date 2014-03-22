#include <stdio.h>

void gre_help(void)
{
  puts("GRE Options:\n"
       "    --gre-seq-present         GRE sequence # present           (default OFF)\n"
       "    --gre-key-present         GRE key present                  (default OFF)\n"
       "    --gre-sum-present         GRE checksum present             (default OFF)\n"
       "    --gre-key NUM             GRE key                          (default RANDOM)\n"
       "    --gre-sequence NUM        GRE sequence #                   (default RANDOM)\n"
       "    --gre-saddr ADDR          GRE IP source IP address         (default RANDOM)\n"
       "    --gre-daddr ADDR          GRE IP destination IP address    (default RANDOM)\n");
}
