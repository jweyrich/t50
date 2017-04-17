/* vim: set ts=2 et sw=2 : */
/** @file main.c */
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h> /* POSIX.1 compliant */
#ifdef __HAVE_DEBUG__
#include <linux/if_ether.h>
#endif
#include <configuration.h>
#include <t50_defines.h>
#include <t50_typedefs.h>
#include <t50_config.h>
#include <t50_netio.h>
#include <t50_errors.h>
#include <t50_cidr.h>
#include <t50_memalloc.h>
#include <t50_modules.h>
#include <t50_randomizer.h>

static pid_t pid = -1;      /* -1 is a trick used when __HAVE_TURBO__ isn't defined. */
static sig_atomic_t child_is_dead = 0; /* Used to kill child process if necessary. */

_NOINLINE static void               initialize(const struct config_options *);
_NOINLINE static modules_table_t *  selectProtocol(const struct config_options * const, int *);
_NOINLINE static const char *       get_ordinal_suffix(unsigned);
_NOINLINE static const char *       get_month(unsigned);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

/**
 * Main function launches all T50 modules
 */
int main(int argc, char *argv[])
{
  struct config_options *co;
  struct cidr           *cidr_ptr;
  modules_table_t       *ptbl;
  int                   proto; /* Used on main loop. */
  time_t                lt;
  struct tm             *tm;

  /* Parse_command_line returns ONLY if there are no errors.
     This must be called before testing user privileges. */
  co = parse_command_line(argv);

  /* User must have root privileges to run T50, unless --help or --version options are found on command line. */
  if (getuid())
    fatal_error("User must have root privilege to run.");

  /* General initializations. */
  initialize(co);

  /* create_socket() handles its own errors before returning. */
  create_socket();

  /* Calculates CIDR for destination address. */
  if (!(cidr_ptr = config_cidr(co)))
    return EXIT_FAILURE;

#ifdef  __HAVE_TURBO__
  /* Creates the forked process if turbo is turned on. */
  if (co->turbo)
  {
    /* if it's necessary to fork a new process... */
    if ((co->ip.protocol == IPPROTO_T50 &&
         co->threshold > (threshold_t)get_number_of_registered_modules()) ||
        (co->ip.protocol != IPPROTO_T50 &&
         co->threshold > 1))
    {
      threshold_t new_threshold;

      if ((pid = fork()) == -1)
#ifdef __HAVE_DEBUG__
        fatal_error("Error creating child process: \"%s\".\nExiting..", strerror(errno));
#else
        fatal_error("Error creating child process");
#endif

      /* Divide the process iterations in main loop between both processes. */
      new_threshold = co->threshold / 2;

      /* Don't let parent process get the extra packet if threshold is odd. */
      if (!IS_CHILD_PID(pid))
        new_threshold += (co->threshold & 1);

      /* Updates threshold for this process. */
      co->threshold = new_threshold;
    }
  }
#endif  /* __HAVE_TURBO__ */

  /* Setting the priority to both parent and child process. */
  if (setpriority(PRIO_PROCESS, PRIO_PROCESS, -15)  == -1)
#ifdef __HAVE_DEBUG__
    fatal_error("Error setting process priority: \"%s\".\nExiting..", strerror(errno));
#else
    fatal_error("Error setting process priority");
#endif

  /* Show launch info only for parent process. */
  if (!IS_CHILD_PID(pid))
  {
    /* Getting the local time. */
    lt = time(NULL);
    tm = localtime(&lt);

    printf("\a\n" PACKAGE " " VERSION " successfully launched at %s %2d%s %d %02d:%02d:%02d\n",
           get_month(tm->tm_mon),
           tm->tm_mday,
           get_ordinal_suffix(tm->tm_mday),
           (tm->tm_year + 1900),
           tm->tm_hour,
           tm->tm_min,
           tm->tm_sec);
  }

  SRANDOM();

  /* Preallocate packet buffer. */
  alloc_packet(INITIAL_PACKET_SIZE);

  /* Selects the initial protocol to use. */
  ptbl = selectProtocol(co, &proto);

  /* MAIN LOOP */
  while (co->flood || co->threshold)
  {
    /* Holds the actual packet size after module function call. */
    size_t size;

    /* Set the destination IP address to RANDOM IP address. */
    co->ip.daddr = cidr_ptr->__1st_addr;
    if (cidr_ptr->hostid)
      co->ip.daddr += RANDOM() % cidr_ptr->hostid;  /* FIXME: Shouldn't be +1? */
    co->ip.daddr = htonl(co->ip.daddr);

    /* Calls the 'module' function to build the packet. */
    co->ip.protocol = ptbl->protocol_id;
    ptbl->func(co, &size);

#ifdef __HAVE_DEBUG__
    /* I'll use this to fine tune the alloc_packet() function, someday! */
    if (size > ETH_DATA_LEN)
      fprintf(stderr, "[DEBUG] Protocol %s packet size (%zu bytes) exceed max. Ethernet packet data length!\n",
              ptbl->acronym, size);
#endif

    /* Try to send the packet. */
    if (unlikely(!send_packet(packet, size, co)))
#ifdef __HAVE_DEBUG__
      error("Packet for protocol %s (%zu bytes long) not sent", ptbl->acronym, size);
    /* continue trying to send other packets on debug mode! */
#else
      fatal_error("Unspecified error sending a packet");
#endif

    /* If protocol if 'T50', then get the next true protocol. */
    if (proto == IPPROTO_T50)
      if ((++ptbl)->func == NULL)
        ptbl = mod_table;

    /* Decrement the threshold only if not flooding! */
    if (!co->flood)
      co->threshold--;
  }

  /* Show termination message only for parent process. */
  if (!IS_CHILD_PID(pid))
  {
    // NOTE: Notice that for a single process pid will be -1! */
    if (pid > 0)
    {
      if (!child_is_dead)
      {
        /* Wait 5 seconds for the child to end... */
        alarm(WAIT_FOR_CHILD_TIMEOUT);
#ifdef __HAVE_DEBUG__
        fputs("\nWaiting for child process to end...\n", stderr);
#endif
        if (wait(NULL) > 0)
          child_is_dead = 1;
        alarm(0);
      }
    }

    /* Finally we close the raw socket. */
    close_socket();

    lt = time(NULL);
    tm = localtime(&lt);

    printf("\a\n" PACKAGE " " VERSION " successfully finished at %s %2d%s %d %02d:%02d:%02d\n",
           get_month(tm->tm_mon),
           tm->tm_mday,
           get_ordinal_suffix(tm->tm_mday),
           (tm->tm_year + 1900),
           tm->tm_hour,
           tm->tm_min,
           tm->tm_sec);
  }

  /* Everything went well. Exit. */
  return 0;
}
#pragma GCC diagnostic pop

/* This function handles interruptions. */
static void signal_handler(int signal)
{
  /* NOTE: SIGALRM and SIGCHLD will happen only in parent process! */
  if (signal == SIGALRM)
  {
    if (!IS_CHILD_PID(pid))   // to be sure...
      kill(pid, SIGKILL);
    return;
  }

  /* Child process terminated? */
  if (signal == SIGCHLD)
  {
    child_is_dead = 1;
    return;
  }

  close_socket();

  /* The shell documentation (bash) specifies that a process,
     when exits because a signal, must return 128+signal#. */
  exit(128 + signal);
}

void initialize(const struct config_options *co)
{
  static struct sigaction sa = { .sa_handler = signal_handler, .sa_flags = SA_RESTART };
  static sigset_t sigset;

  /* Blocks SIGTSTP avoiding ^Z behavior. */
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGTSTP);
#ifndef __HAVE_DEBUG__
  sigaddset(&sigset, SIGTRAP);
#endif
  sigprocmask(SIG_BLOCK, &sigset, NULL);

  /* --- Initialize signal handlers --- */
  /* All these signals are handled by our handle. */
  sigaction(SIGPIPE, &sa, NULL);
  sigaction(SIGINT,  &sa, NULL);
  sigaction(SIGCHLD, &sa, NULL);
  sigaction(SIGALRM, &sa, NULL);

  /* --- To simplify things, make sure stdout is unbuffered
         (otherwise, it's line buffered). --- */
  fflush(stdout);
  setvbuf(stdout, NULL, _IONBF, 0);

  /* --- Show some messages. */
  if (co->flood)
    puts("Entering flood mode...");
  else
    printf("Sending %u packets...\n", co->threshold);

#ifdef __HAVE_TURBO__
  if (co->turbo)
    puts("Turbo mode active...");
#endif

  if (co->bits)
    puts("Performing stress testing...");

  puts("Hit Ctrl+C to stop...");
}

/* Auxiliary function to return the [constant] ordinary suffix string for a number. */
const char *get_ordinal_suffix(unsigned n)
{
  static const char *suffixes[] = { "st", "nd", "rd", "th" };

  /* FIX: 11, 12 & 13 have 'th' suffix, not 'st, nd or rd'. */
  if ((n < 11) || (n > 13))
    switch (n % 10)
    {
    case 1:
      return suffixes[0];
    case 2:
      return suffixes[1];
    case 3:
      return suffixes[2];
    }

  return suffixes[3];
}

/* Auxiliary function to return the [constant] string for a month.
   NOTE: 'n' must be between 0 and 11.
   NOTE: This routine is here just 'cause we need months in english. */
const char *get_month(unsigned n)
{
  /* Months */
  static const char *const months[] =
  {
    "Jan", "Feb", "Mar", "Apr", "May",  "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov",  "Dec"
  };

  if (n > 11)
    return "???";

  return months[n];
}

/* Selects the initial protocol based on the configuration. */
modules_table_t *selectProtocol(const struct config_options *const co, int *proto)
{
  modules_table_t *ptbl;

  ptbl = mod_table;
  if ((*proto = co->ip.protocol) != IPPROTO_T50)
    ptbl += co->ip.protoname;

  return ptbl;
}
