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

int check_threshold(const struct config_options * const __restrict__ co)
{
  char *s;

  if (co->ip.protocol == IPPROTO_T50)
  {
    threshold_t minThreshold = (threshold_t)get_number_of_registered_modules();

    if (co->threshold < minThreshold)
    {
      if (asprintf(&s, "Protocol %s cannot have threshold smaller than %d", 
            mod_table[co->ip.protoname].acronym,
            minThreshold) == -1)
      {
        fprintf(stderr, "ERROR allocating temporary string space.\n");
        exit(EXIT_FAILURE);
      }

      ERROR(s);
      free(s);

      return FALSE;
    }
  }
  else
  {
    if (co->threshold < 1)
    {
      if (asprintf(&s, "Protocol %s cannot have threshold smaller than 1",
              mod_table[co->ip.protoname].acronym) == -1)
      {
        fprintf(stderr, "ERROR allocating temporary string space.\n");
        exit(EXIT_FAILURE);
      }

      ERROR(s);
      free(s);

      return FALSE;
    }
  }

  return TRUE;
}

