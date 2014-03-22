#include <stdio.h>

void ipsec_help(void)
{
  puts("IPSEC Options:\n"
       "    --ipsec-ah-length NUM     IPSec AH header length           (default NONE)\n"
       "    --ipsec-ah-spi NUM        IPSec AH SPI                     (default RANDOM)\n"
       "    --ipsec-ah-sequence NUM   IPSec AH sequence #              (default RANDOM)\n"
       "    --ipsec-esp-spi NUM       IPSec ESP SPI                    (default RANDOM)\n"
       "    --ipsec-esp-sequence NUM  IPSec ESP sequence #             (default RANDOM)\n");
}
