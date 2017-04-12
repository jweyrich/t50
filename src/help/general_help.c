/* vim: set ts=2 et sw=2 : */
/** @file general_help.c */
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

#include <stdio.h>
#include <t50_modules.h>

/** Common options help function. */
void general_help(void)
{
  puts("Common Options:\n"
       "    --threshold NUM           Threshold of packets to send     (default 1000)\n"
       "    --flood                   This option supersedes the \'threshold\'\n"
       "    --encapsulated            Encapsulated protocol (GRE)      (default OFF)\n"
       " -B,--bogus-csum              Bogus checksum                   (default OFF)\n"
#ifdef  __HAVE_TURBO__
       "    --turbo                   Extend the performance           (default OFF)\n"
#endif  /* __HAVE_TURBO__ */
       " -l,--list-protocols          List all available protocols\n"
       " -v,--version                 Print version and exit\n"
       " -h,--help                    Display this help and exit\n");
}

