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

static pid_t pid = -1;      /* -1 is a trick used when __HAVE_TURBO__ isn't defined. */

static void initialize(void);
static const char *getOrdinalSuffix(unsigned);
static const char *getMonth(unsigned);

/* Main function launches all T50 modules */
int main(int argc, char *argv[])
{
  struct config_options *co;  /* Pointer to options. */
  struct cidr *cidr_ptr;      /* Pointer to cidr host id and 1st ip address. */

  modules_table_t *ptbl;      /* Pointer to modules table */
  int num_modules;            /* Holds number of modules in modules table. */

  initialize();

  /* Configuring command line interface options. */
  co = getConfigOptions(argc, argv);

  /* This is a requirement of t50. Previously on checkConfigOptions(). */
  if (getuid())
  {
    ERROR("User must have root priviledge to run.");
    return EXIT_FAILURE;
  }

  /* Validating command line interface options. */
  /* NOTE: checkConfigOptions now returns 0 if failure. Makes more sense! */
  if (!checkConfigOptions(co))
    return EXIT_FAILURE;

  num_modules = getNumberOfRegisteredModules();

  /* Sanitizing the threshold. */
  if (co->ip.protocol == IPPROTO_T50)
    co->threshold -= (co->threshold % num_modules);

  /* Setting socket file descriptor. */
  /* NOTE: createSocket() handles its errors before returning. */
  createSocket();

  /* Setup random seed using current date/time timestamp. */
  /* NOTE: Random seed don't need to be so precise! */
  srandom(time(NULL));

  /* 
     FIXME: Is threshold calculated right, in turbo mode?

            To my knowledge, if threshold == 1, no child process should be
            created in turbo mode. Even more: if the protocol choosen is
            "T50", then no child process should be created if threshold is
            lesser than "num_of_modules".

            If threshold is even, both parent and child processes should send
            "threshold / 2" packets. But if it is odd, the parent process should
            send "threshold / 2" packets, while the child process should send
            "(threshold / 2) - 1" packets.

            The possible fix for this problem are below, commented as
            "FIXME: Possible fix (#1)".
  */

#ifdef  __HAVE_TURBO__
  /* Entering in TURBO. */
  if (co->turbo)
  {
    /* FIXME: Possible fix (#1) */
#if 0
    if ((co->ip.protocol == IPROTO_T50 && co->threshold > num_modules) || 
        (cp->ip.protocol != IPPROTO_T50 && co->threshold > 1))
    {
      threshold_t new_threshold;

#endif
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

      /* FIXME: Possible fix (#1) */
#if 0
      new_threshold = co->threshold / 2; 

      /* child process get threshold minus one, if given threshold is odd. */
      if ((co->threshold % 2) && !pid)
        new_threshold--;

      co->threshold = new_threshold;
#endif
    }
#endif  /* __HAVE_TURBO__ */

  /* Calculates CIDR for destination address. */
  cidr_ptr = config_cidr(co->bits, co->ip.daddr);

  /* Show launch info only for parent process. */
  if (!IS_CHILD_PID(pid))
  {
    time_t lt;
    struct tm *tm;

    /* Getting the local time. */
    lt = time(NULL); 
    tm = localtime(&lt);

    fprintf(stderr, "\b\n%s %s successfully launched on %s %2d%s %d %.02d:%.02d:%.02d\n",
      PACKAGE,  VERSION, getMonth(tm->tm_mon), tm->tm_mday, getOrdinalSuffix(tm->tm_mday),
      (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
  }

  /* Execute if flood or while threshold greater than 0. */
  while (co->flood || (co->threshold-- > 0))
  {
    /* Holds the actual packet size after module function call. */
    size_t size;

    /* Set the destination IP address to RANDOM IP address. */
    if (cidr_ptr->hostid)
      co->ip.daddr = htonl(cidr_ptr->__1st_addr + 
        (random() % cidr_ptr->hostid));

    /* Sending ICMP/IGMP/TCP/UDP/... packets. */
    if (co->ip.protocol != IPPROTO_T50)
    {
      /* Get the protocol. */
      ptbl = &mod_table[co->ip.protoname];
      co->ip.protocol = ptbl->protocol_id;

      /* Launch t50 module. */
      ptbl->func(co, &size);
      
      sendPacket(packet, size, co);
    }
    else
    {
      /* NOTE: Using single pointer instead of calculating
               the pointers in every iteration. */
      /* Sending T50 packets. */
      for (ptbl = mod_table; ptbl->func != NULL; ptbl++)
      {
        /* Getting the correct protocol. */
        co->ip.protocol = ptbl->protocol_id;

        /* Launching t50 module. */
        ptbl->func(co, &size);

        sendPacket(packet, size, co);
      }

      /* Sanitizing the threshold. */
      co->threshold -= num_modules - 1;

      /* Reseting protocol. */
      co->ip.protocol = IPPROTO_T50;
    }
  }

  /* Show termination message only for parent process. */
  if (!IS_CHILD_PID(pid))
  {
    time_t lt;
    struct tm *tm;

    /* FIX: We need to wait() for child processes only if we forked one! */
#ifdef  __HAVE_TURBO__
    int status;

    wait(&status);
#endif

    /* FIX: To graciously end the program, only the parent process can close the socket. */
    closeSocket();

    /* Getting the local time. */
    lt = time(NULL); 
    tm = localtime(&lt);

    fprintf(stderr, "\b\n%s %s successfully finished on %s %2d%s %d %.02d:%.02d:%.02d\n",
      PACKAGE,  VERSION, getMonth(tm->tm_mon), tm->tm_mday, getOrdinalSuffix(tm->tm_mday),
      (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
  }

  return 0;
}

/* This function handles interruptions. */
static void signal_handler(int signal)
{
  /* Make sure the socket descriptor is closed. 
     FIX: But only if this is the parent process. Closing the cloned descriptor on the
          child process can be catastrophic to the parent. */
#ifdef __HAVE_TURBO__
  if (!IS_CHILD_PID(pid))
#endif
    closeSocket();

  /* FIX: The shell documentation (bash) specifies that a process
          when exits because a signal, must return 128+signal#. */
  exit(128 + signal);
}

static void initialize(void)
{
  /* NOTE: See 'man 2 signal' */
  struct sigaction sa;

  /* --- Initialize signal handlers --- */

  /* Using sig*() functions for compability. */
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART; /* same signal() semantics?! */

  /* Trap all "interrupt" signals, except SIGKILL, SIGSTOP and SIGSEGV */
  sa.sa_handler = signal_handler;
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

  /* --- Make sure stdout is unbuffered. --- */
  fflush(stdout);
  setvbuf(stdout, NULL, _IONBF, 0); 
}

/* Auxiliary function to return the [constant] ordinary suffix string for a number. */
static const char *getOrdinalSuffix(unsigned n)
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

static const char *getMonth(unsigned n)
{
  /* Months */
  static const char * const months[] =
    { "Jan", "Feb", "Mar", "Apr", "May",  "Jun",
      "Jul", "Aug", "Sep", "Oct", "Nov",  "Dec" };

  if (n > 11)
    return "";

  return months[n];
}
