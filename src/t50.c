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
#include <sys/wait.h>

/* Global variables */
static pid_t pid = 1;  /* NOTE: this is a trick when "turbo" is not used. */
static socket_t fd;

/* Months */
static const char *const months[] =
  { "Jan", "Feb", "Mar", "Apr", "May",  "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov",  "Dec" };

/* This function handles Control-C (^C) */
static void ctrlc(int32_t signal)
{
  UNUSED_PARAM(signal);

  close(fd);

  /* NOTE: SIGSEGV is a fatal signal. I think handle it doesn't make sense! */
#if 0
  if (signal == SIGSEGV)
  {
      perror("Internal error: buffer overflow. SIGSEGV received.\n");
      exit(EXIT_FAILURE);
  }
#endif

  /* FIXME: Is returning EXIT_SUCCESS a good idea?
            Maybe we should return something like "2" to
            represent an interruption...

            If so, must change "initializeSignalHandlers()", below, to
            treat some traps differently. */
  exit(EXIT_SUCCESS);
}

static void initializeSignalHandlers(void)
{
  /* NOTE: See 'man 2 signal' */
  struct sigaction sa;

  /* Using sig*() functions for compability. */
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART; /* signal() semantics */


  /* Trap all "interrupt" signals, except SIGKILL, SIGSTOP and SIGSEGV */
  sa.sa_handler = ctrlc;
  sigaction(SIGHUP,  &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);
  sigaction(SIGINT,  &sa, NULL);
  sigaction(SIGQUIT, &sa, NULL);
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGTRAP, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGTSTP, &sa, NULL);
#ifdef  __HAVE_TURBO__
  sigaction(SIGCHLD, &sa, NULL);
#endif
}

/* Auxiliary function to return the ordinary suffix for a number. */
static const char *getOrdinalSuffix(unsigned int n)
{
  static const char *suffixes[] = { "st", "nd", "rd", "th" };

  /* FIX: 11, 12 & 13 have 'th' suffix, not 'st, nd or rd'. */
  if ((n < 11) || (n > 13))
    switch (n % 10) {
      case 1: return suffixes[0];
      case 2: return suffixes[1];
      case 3: return suffixes[2];
    }

  return suffixes[3];
}

/* Main function launches all T50 modules */
int main(int argc, char *argv[])
{
  struct config_options *o; /* Pointer to options. */
  struct cidr *cidr_ptr; /* Pointer to cidr host id and 1st ip address. */

  modules_table_t *ptbl; /* Pointer to modules table */
  int num_modules;       /* Holds number of modules in modules table. */

  initializeSignalHandlers();

  /* Configuring command line interface options. */
  o = getConfigOptions(argc, argv);

  /* This is a requirement of t50. Previously on checkConfigOptions(). */
  if (!getuid())
  {
    ERROR("User muse have root priviledge to run.");
    return EXIT_FAILURE;
  }

  /* Validating command line interface options. */
  /* NOTE: checkConfigOptions now returns 0 if failure. Makes more sense! */
  if (!checkConfigOptions(o))
    return EXIT_FAILURE;

  num_modules = getNumberOfRegisteredModules();

  /* Sanitizing the threshold. */
  if (o->ip.protocol == IPPROTO_T50)
    o->threshold -= (o->threshold % num_modules);

  /* Setting socket file descriptor. */
  /* NOTE: createSocket() handles its errors before returning. */
  fd = createSocket();

  /* Setup random seed using current date/time timestamp. */
  /* NOTE: Random seed don't need to be so precise! */
  srandom(time(NULL));

#ifdef  __HAVE_TURBO__
  /* Entering in TURBO. */
  if (o->turbo)
  {
    if ((pid = fork()) == -1)
    {
      perror("Error creating child process. Exiting...");
      return EXIT_FAILURE;
    }

    /* Setting the priority to both parent and child process to highly favorable scheduling value. */
    /* FIXME: Why not setup this value when t50 runs as a single process? */
    if (setpriority(PRIO_PROCESS, PRIO_PROCESS, -15)  == -1)
    {
      perror("Error setting process priority. Exiting...");
      return EXIT_FAILURE;
    }
  }
#endif  /* __HAVE_TURBO__ */

  /* Calculates CIDR for destination address. */
  cidr_ptr = config_cidr(o->bits, o->ip.daddr);

  /* Show launch info only for parent process. */
  if (pid)
  {
    time_t lt;
    struct tm *tm;

    /* Getting the local time. */
    lt = time(NULL); 
    tm = localtime(&lt);

    /* FIXME: Why use '\b\r' at the beginning?! */
    fprintf(stderr, "\b\r%s %s successfully launched on %s %2d%s %d %.02d:%.02d:%.02d\n",
      PACKAGE,  VERSION, months[tm->tm_mon], tm->tm_mday, getOrdinalSuffix(tm->tm_mday),
      (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
  }

  /* Execute if flood or while threshold greater than 0. */
  while (o->flood || o->threshold--)
  {
    /* Set the destination IP address to RANDOM IP address. */
    if (cidr_ptr->hostid)
      o->ip.daddr = htonl(cidr_ptr->__1st_addr + 
        (random() % cidr_ptr->hostid));

    /* Sending ICMP/IGMP/TCP/UDP/... packets. */
    if (o->ip.protocol != IPPROTO_T50)
    {
      /* Get the protocol. */
      ptbl = &mod_table[o->ip.protoname];
      o->ip.protocol = ptbl->protocol_id;

      /* Launch t50 module. */
      if (ptbl->func(fd, o))
      {
        ERROR("Error sending packet");
        close(fd);

        return EXIT_FAILURE;
      }
    }
    else
    {
      /* NOTE: Using single pointer instead of calculating
               the pointers in every iteration. */
      /* Sending T50 packets. */
      for (ptbl = mod_table; ptbl->func != NULL; ptbl++)
      {
        /* Getting the correct protocol. */
        o->ip.protocol = ptbl->protocol_id;

        /* Launching t50 module. */
        if (ptbl->func(fd, o))
        {
          ERROR("Error sending packet");
          close(fd);

          return EXIT_FAILURE;
        }
      }

      /* Sanitizing the threshold. */
      /* FIXME: Is this correct? */
      o->threshold -= num_modules - 1;

      /* Reseting protocol. */
      o->ip.protocol = IPPROTO_T50;
    }
  }

#ifdef  __HAVE_TURBO__
  /* Make sure the child process have exited. */
  if (o->turbo)
  {
    int status;

    waitpid(-1, &status, 0);
  }
#endif

  /* Closing the socket. */
  close(fd);

  /* Show termination message only for parent process. */
  if (pid)
  {
    time_t lt;
    struct tm *tm;

    /* Getting the local time. */
    lt = time(NULL); 
    tm = localtime(&lt);

    /* FIXME: Why use '\b\r' at the beginning?! */
    fprintf(stderr, "\b\r%s %s successfully finished on %s %2d%s %d %.02d:%.02d:%.02d\n",
      PACKAGE,  VERSION, months[tm->tm_mon], tm->tm_mday, getOrdinalSuffix(tm->tm_mday),
      (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
  }

  return 0;
}
