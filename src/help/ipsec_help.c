/* vim: set ts=2 et sw=2 : */
/** @file ipsec_help.c */
/*
 *  T50 - Experimental Mixed Packet Injector
 *
 *  Copyright (C) 2010 - 2015 - T50 developers
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <common.h>

/** IPSec options help. */
void ipsec_help(void)
{
  puts("IPSEC Options:\n"
       "    --ipsec-ah-length NUM     IPSec AH header length           (default NONE)\n"
       "    --ipsec-ah-spi NUM        IPSec AH SPI                     (default RANDOM)\n"
       "    --ipsec-ah-sequence NUM   IPSec AH sequence #              (default RANDOM)\n"
       "    --ipsec-esp-spi NUM       IPSec ESP SPI                    (default RANDOM)\n"
       "    --ipsec-esp-sequence NUM  IPSec ESP sequence #             (default RANDOM)\n");
}

