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

/* Evaluate the threshold configuration */
static int checkThreshold(const struct config_options * const __restrict__);

/* Validate options 
   NOTE: This function must be called before forking!
   Returns 0 on failure. */
int checkConfigOptions(const struct config_options * const __restrict__ co)
{
  assert(co != NULL);

  /* Warns about missed target. */
  if (co->ip.daddr == INADDR_ANY)
  {
    ERROR("Need target address. Try --help for usage");
    return FALSE;
  }

  /* FIX: Deleted 'bits' validation code. Code already in getIpAndCidrFromString() at config.c. */

  /* Sanitizing the TCP Options SACK_Permitted and SACK Edges. */
  if (TEST_BITS(co->tcp.options, TCP_OPTION_SACK_OK) &&
      TEST_BITS(co->tcp.options, TCP_OPTION_SACK_EDGE))
  {
    ERROR("TCP options SACK-Permitted and SACK Edges are not allowed");
    return FALSE;
  }

  /* Sanitizing the TCP Options T/TCP CC and T/TCP CC.ECHO. */
  if (TEST_BITS(co->tcp.options, TCP_OPTION_CC) && (co->tcp.cc_echo))
  {
    ERROR("TCP options T/TCP CC and T/TCP CC.ECHO are not allowed");
    return FALSE;
  }

  if (!checkThreshold(co))
    return FALSE;

  if (!co->flood)
  {
#ifdef  __HAVE_TURBO__
    /* Sanitizing TURBO mode. */
    if (co->turbo)
    {
      ERROR("turbo mode is only available in flood mode");
      return FALSE;
    }
#endif  /* __HAVE_TURBO__ */
  }
  else /* if (co->flood) isn't 0 */
  {
    /* Warning FLOOD mode. */
    puts("Entering in flood mode...");

#ifdef  __HAVE_TURBO__
    if (co->turbo)
      puts("Activating turbo...");
#endif  /* __HAVE_TURBO__ */

    /* Warning CIDR mode. */
    if (co->bits != 0)
      puts("Performing DDoS...");

    puts("Hit CTRL+C to break.");
  }

  /* Returning. */
  return TRUE;
}

static int checkThreshold(const struct config_options * const __restrict__ co)
{
  char *s;

  if (co->ip.protocol == IPPROTO_T50)
  {
    threshold_t minThreshold = (threshold_t)getNumberOfRegisteredModules();

    if (co->threshold < minThreshold)
    {
      asprintf(&s, "Protocol %s cannot have threshold smaller than %d", 
        mod_table[co->ip.protoname].acronym,
        minThreshold);

      ERROR(s);
      free(s);

      return FALSE;
    }
  }
  else
  {
    if (co->threshold < 1)
    {
      asprintf(&s, "Protocol %s cannot have threshold smaller than 1",
              mod_table[co->ip.protoname].acronym);

      ERROR(s);
      free(s);

      return FALSE;
    }
  }

  return TRUE;
}

