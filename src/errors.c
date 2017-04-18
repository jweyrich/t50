/* vim: set ts=2 et sw=2 : */
/** @file errors.c */
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

// Needed for asprintf().
#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <configuration.h>

#ifdef __HAVE_DEBUG__
#include <time.h>
#include <string.h>

#define LOG_FILE "/var/log/t50_debug.log"

static void log_datetime(FILE *f)
{
  char s[28];
  time_t t;
  struct tm tm;

  t = time(NULL);
  gmtime_r(&t, &tm);
  strftime(s, sizeof(s) - 1, "%m/%d/%Y %H:%M:%S UTC", &tm);
  fprintf(f, "%s - ", s);
}
#endif

/* --- Using vfprintf for flexibility. */
static void verror(const char * const fmt, va_list args)
{
  char *str;

  if ((asprintf(&str, PACKAGE ": %s\n", fmt)) == -1)
  {
    fputs(PACKAGE ": Unknown error (not enough memory?).\n", stderr);
    exit(EXIT_FAILURE);
  }

  vfprintf(stderr, str, args);

#ifdef __HAVE_DEBUG__
  {
    FILE *f;

    if (f = fopen(LOG_FILE, "at"))
    {
      log_datetime(f);
      vfprintf(f, str, args);
      fclose(f);
    }
  }
#endif

  free(str);
}

/**
 * Standard error reporting routine. Non fatal version.
 */
void error(const char * const fmt, ...)
{
  va_list args;

  va_start(args, fmt);
  verror(fmt, args);
  va_end(args);
}

/**
 * Standard error reporting routine. Fatal Version.
 *
 * This function never returns!
 */
void fatal_error(const char * const fmt, ...)
{
  va_list args;

  fputs("\a\n", stderr);  /* BEEP! */
  va_start(args, fmt);
  verror(fmt,args);
  va_end(args);

  /* As expected. exit if a failure. */
  exit(EXIT_FAILURE);
}

