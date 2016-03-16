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

#include <common.h>
#include <sys/wait.h> /* POSIX.1 compliant */
#ifdef __HAVE_DEBUG__
#include <linux/if_ether.h>
#endif

static pid_t pid = -1;      /* -1 is a trick used when __HAVE_TURBO__ isn't defined. */
static int child_is_dead = 0; /* Used to kill child process if necessary. */

static void             initialize(const struct config_options *);
static modules_table_t *selectProtocol(const struct config_options * const, int *);
static const char *     get_ordinal_suffix(unsigned);
static const char *     get_month(unsigned);

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

  /* Parse_command_line returns ONLY if there are no errors. 
     This must be called before testing user privileges. */
  co = parse_command_line(argv);

  /* User must have root privileges to run T50, unless --help or --version options are found on command line. */
  if (getuid())
    fatal_error("User must have root priviledge to run.");

  /* General initializations. */
  initialize(co);

  /* Create_socket() handles its own errors before returning. */
  if (!create_socket())
    return EXIT_FAILURE;

  /* Calculates CIDR for destination address. */
  if ((cidr_ptr = config_cidr(co)) == NULL)
    return EXIT_FAILURE;

#ifdef  __HAVE_TURBO__
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
        fatal_error("Error creating child process (\"%s\").\nExiting...", strerror(errno));

      /* Divide the process iterations in main loop between processes. 
         Since we have only 2 processes, max, i'll divide by 2. */
      new_threshold = co->threshold / 2;

      /* FIX: Ooops! Parent process get the extra packet, if threshold is odd. */
      if (!IS_CHILD_PID(pid))
        new_threshold += (co->threshold & 1);

      /* Updates threshold for this process. */
      co->threshold = new_threshold;
    }
  }
#endif  /* __HAVE_TURBO__ */

  /* Setting the priority to both parent and child process to highly favorable scheduling value. */
  if (setpriority(PRIO_PROCESS, PRIO_PROCESS, -15)  == -1)
    fatal_error("Error setting process priority (\"%s\"). Exiting...", strerror(errno));

  /* Show launch info only for parent process. */
  if (!IS_CHILD_PID(pid))
  {
    time_t lt;
    struct tm *tm;

    /* Getting the local time. */
    lt = time(NULL);
    tm = localtime(&lt);

    printf("\a\n" PACKAGE " " VERSION " successfully launched at %s %2d%s %d %.02d:%.02d:%.02d\n",
           get_month(tm->tm_mon),
           tm->tm_mday,
           get_ordinal_suffix(tm->tm_mday),
           (tm->tm_year + 1900),
           tm->tm_hour,
           tm->tm_min,
           tm->tm_sec);
  }

  /* NOTE: Changed the random seed init to here to make
           sure both processes have it's own! */
  SRANDOM();

  /* Preallocate packet buffer. */
  alloc_packet(INITIAL_PACKET_SIZE);

  /* Selects the initial protocol to use. */
  /* NOTE: Minor hack: back here from the last branch to avoid page fault using ptbl pointer. */
  ptbl = selectProtocol(co, &proto);  /* No problems here. ptbl will never be NULL. */

  /* MAIN LOOP: Executed if flooding or if threshold is given. */
  while (co->flood || co->threshold)
  {
    /* Holds the actual packet size after module function call. */
    size_t size;

    /* Set the destination IP address to RANDOM IP address. */
    /* NOTE: The previous code did not account for 'hostid == 0'! */
    co->ip.daddr = cidr_ptr->__1st_addr;

    if (cidr_ptr->hostid)
      co->ip.daddr += RANDOM() % cidr_ptr->hostid;  /* FIXME: Shouldn't be +1? */ 

    /* We need the address in network order now. */
    co->ip.daddr = htonl(co->ip.daddr);

    /* Calls the 'module' function and sends the packet. */
    co->ip.protocol = ptbl->protocol_id;

    ptbl->func(co, &size);

#ifdef __HAVE_DEBUG__
    /* I'll use this to fine tune the alloc_packet() function, someday! */
    if (size > ETH_DATA_LEN)
      fprintf(stderr, "[DEBUG] Protocol %s packet size (%zd bytes) exceed max. Ethernet packet data length!\n",
              ptbl->acronym, size);
#endif

    /* Try to send the packet. */
    if (!send_packet(packet, size, co))
#ifdef __HAVE_DEBUG__
      error("Packet for protocol %s (%zd bytes long) not sent.", ptbl->acronym, size);
      /* continue trying to send other packets on debug mode! */
#else
      fatal_error("Unspecified error sending a packet.");
#endif

    /* If protocol if 'T50', then get the next true protocol. */
    if (proto == IPPROTO_T50)
      if ((++ptbl)->func == NULL)
        ptbl = mod_table;

    /* FIX: Just to make sure we do not decrement the threshold value if isn't necessary! */
    if (!co->flood)
      co->threshold--;
  }


  /* Show termination message only for parent process. */
  if (!IS_CHILD_PID(pid))
  {
    time_t lt;
    struct tm *tm;

    if (!child_is_dead)
    {
      alarm(5);
      if (waitpid(pid, NULL, 0) == -1)
        child_is_dead = 1;
      alarm(0);
    }

    if (!child_is_dead)
      kill(pid, SIGKILL);

    close_socket();

    /* Getting the local time. */
    lt = time(NULL);
    tm = localtime(&lt);

    printf("\a\n" PACKAGE " " VERSION " successfully finished at %s %2d%s %d %.02d:%.02d:%.02d\n",
           get_month(tm->tm_mon),
           tm->tm_mday,
           get_ordinal_suffix(tm->tm_mday),
           (tm->tm_year + 1900),
           tm->tm_hour,
           tm->tm_min,
           tm->tm_sec);
  }

  return 0;
}
#pragma GCC diagnostic pop

/* This function handles interruptions. */
static void signal_handler(int signal)
{
  /* Make sure the socket descriptor is closed.
     FIX: But only if this is the parent process. Closing the cloned descriptor on the
          child process can be catastrophic to the parent.
     NOTE: I realize that the act of closing descriptors are reference counted.
           Keept the logic just in case! */
#ifdef __HAVE_TURBO__
  if (!IS_CHILD_PID(pid))
  {
    if (signal == SIGCHLD)
      child_is_dead = 1;

    /* Ungracefully kills the child process! */
    if (!child_is_dead)
      kill(pid, SIGKILL);
#endif

    close_socket();

#ifdef __HAVE_TURBO__
  }
#endif

  /* The shell documentation (bash) specifies that a process
     when exits because a signal, must return 128+signal#. */
  exit(128 + signal);
}

static void initialize(const struct config_options *co)
{
  /* NOTE: See 'man 2 signal' */
  static struct sigaction sa;

  /* --- Initialize signal handlers --- */

  /* Using sig*() functions for compability. */
  sigemptyset(&sa.sa_mask);
  //sa.sa_flags = SA_RESTART;

  /* Trap all "interrupt" signals, except SIGKILL, SIGSTOP and SIGSEGV (uncatchable, accordingly to 'man 7 signal').
     This is necessary to close the socket when terminating the parent process. */
  sa.sa_handler = signal_handler;

  sigaction(SIGHUP,  &sa, NULL);
  //sigaction(SIGPIPE, &sa, NULL);    /* FIXME: Is SIGPIPE handler really necessary? */
  sigaction(SIGINT,  &sa, NULL);
  sigaction(SIGQUIT, &sa, NULL);
  //sigaction(SIGTRAP, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  //sigaction(SIGTSTP, &sa, NULL);

  sa.sa_handler = SIG_IGN;
  sigaction(SIGCHLD, &sa, NULL);

  /* --- To simplify things, make sure stdout is unbuffered
         (otherwise, it's line buffered). --- */
  fflush(stdout);
  setvbuf(stdout, NULL, _IONBF, 0);

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
static const char * _NOINLINE get_ordinal_suffix(unsigned n)
{
  static const char *suffixes[] = { "st", "nd", "rd", "th" };

  /* FIX: 11, 12 & 13 have 'th' suffix, not 'st, nd or rd'. */
  if ((n < 11) || (n > 13))
    switch (n % 10)
    {
    case 1: return suffixes[0];
    case 2: return suffixes[1];
    case 3: return suffixes[2];
    }

  return suffixes[3];
}

/* Auxiliary function to return the [constant] string for a month.
   NOTE: 'n' must be between 0 and 11. */
static const char * _NOINLINE get_month(unsigned n)
{
  /* Months */
  static const char *const months[] =
  {
    "Jan", "Feb", "Mar", "Apr", "May",  "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov",  "Dec"
  };

  if (n > 11)
    return "";

  return months[n];
}

/* Selects the initial protocol based on the configuration. */
static modules_table_t *selectProtocol(const struct config_options *const co, int *proto)
{
  modules_table_t *ptbl;

  ptbl = mod_table;
  if ((*proto = co->ip.protocol) != IPPROTO_T50)
    ptbl += co->ip.protoname;

  return ptbl;
}
