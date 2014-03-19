/*
 *  T50 - Experimental Mixed Packet Injector
 *
 *  Copyright (C) 2010 - 2014 - T50 developers
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

/* Validate options */
int checkConfigOptions(const struct config_options *o)
{
  int minThreshold;

  /* Check if we have root priviledges. */
  if ( getuid() != 0 )
  {
    ERROR("you must have root privilege");
    return 0;
  }

  /* Warning missed target. */
  if (o->ip.daddr == INADDR_ANY)
  {
    ERROR("Need target address. Try --help for usage");
    return 0;
  }

  /* Sanitizing the CIDR. */
  if ((o->bits != 0) && ((o->bits < CIDR_MINIMUM) || (o->bits > CIDR_MAXIMUM)))
  {
    /* NOTE: Arbitrary array size... 48 is qword aligned on stack, i suppose! */
    char errstr[48];

    sprintf(errstr, "CIDR must be beewten %d and %d", CIDR_MINIMUM, CIDR_MAXIMUM);
    ERROR(errstr);
    return 0;
  }

  /* Sanitizing the TCP Options SACK_Permitted and SACK Edges. */
  if (TEST_BITS(o->tcp.options, TCP_OPTION_SACK_OK) &&
      TEST_BITS(o->tcp.options, TCP_OPTION_SACK_EDGE))
  {
    ERROR("TCP options SACK-Permitted and SACK Edges are not allowed");
    return 0;
  }

  /* Sanitizing the TCP Options T/TCP CC and T/TCP CC.ECHO. */
  if (TEST_BITS(o->tcp.options, TCP_OPTION_CC) && (o->tcp.cc_echo))
  {
    ERROR("TCP options T/TCP CC and T/TCP CC.ECHO are not allowed");
    return 0;
  }

  if (!o->flood)
  {
#ifdef  __HAVE_TURBO__
    /* Sanitizing TURBO mode. */
    if (o->turbo)
    {
      ERROR("turbo mode is only available in flood mode");
      return 0;
    }
#endif  /* __HAVE_TURBO__ */

    /* Sanitizing the threshold. */
    minThreshold = getNumberOfRegisteredModules();

    if ((o->ip.protocol == IPPROTO_T50) && (o->threshold < (unsigned)minThreshold))
    {
      fprintf(stderr,
          "%s: protocol %s cannot have threshold smaller than %d\n",
          PACKAGE,
          mod_table[o->ip.protoname].acronym,
          minThreshold);
      return 0;
    }
  }
  else /* if (o->flood) isn't 0 */
  {
    /* Warning FLOOD mode. */
    puts("entering in flood mode...");

#ifdef  __HAVE_TURBO__
    if (o->turbo)
      puts("activating turbo...");
#endif  /* __HAVE_TURBO__ */

    /* Warning CIDR mode. */
    if (o->bits != 0)
      puts("performing DDoS...");

    puts("hit CTRL+C to break.");
  }

  /* Returning. */
  return 1;
}
