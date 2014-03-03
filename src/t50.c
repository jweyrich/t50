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

  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;

  /* Ignoring signals. */
  sigaction(SIGHUP,  &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

  sa.sa_handler = ctrlc;
  /* Handling signals. */
  sigaction(SIGINT,  &sa, NULL);
  //sigaction(SIGILL, &sa, NULL); /* not necessary */
  sigaction(SIGQUIT, &sa, NULL);
  sigaction(SIGABRT, &sa, NULL);
  sigaction(SIGTRAP, &sa, NULL);
  //sigaction(SIGKILL, &sa, NULL); /* SIGKILL & SIGSTOP cannot be caught or ignored */
  //sigaction(SIGSTOP, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGTSTP, &sa, NULL);
  //sigaction(SIGSEGV, &sa, NULL); /* segmentation fault is a severe error. */
                                   /* Don't need to be caught here! */
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
  time_t lt;
  struct tm *tm;

  /* Command line interface options. */
  struct config_options *o;

	/* NOTE: Random seed don't need to be so precise! */
  /* Seed to use with 'srand()'. */
  //struct timeval seed;

  /* Counter and random destination address. */
  uint32_t rand_daddr;

  /* CIDR host identifier and first IP address. */
  struct cidr *cidr_ptr;

	int num_modules;

  initializeSignalHandlers();

  /* Configuring command line interface options. */
  o = getConfigOptions(argc, argv);

  /* NOTE: checkConfigOptions now returns TRUE or FALSE, instead of
           EXIT_FAILURE or EXIT_SUCCESS. Makes more sense! */  
  /* Validating command line interface options. */
  if (!checkConfigOptions(o))
    exit(EXIT_FAILURE);

	num_modules = getNumberOfRegisteredModules();

  /* Sanitizing the threshold. */
  if (o->ip.protocol == IPPROTO_T50)
    o->threshold -= (o->threshold % num_modules);

  /* Setting socket file descriptor. */
  fd = sock();

	/* NOTE: Random seed don't need to be so precise! */
  /* Initializing random seed. */
  //gettimeofday(&seed, NULL);
  //srand((unsigned)seed.tv_usec);
  srand(time(NULL));

#ifdef  __HAVE_TURBO__
  /* Entering in TURBO. */
  if (o->turbo)
  {
    if ((pid = fork()) == -1)
    {
      perror("Error creating child process. Exiting...");
      exit(EXIT_FAILURE);
    }

    /* Setting the priority to lowest (?) one. */
    if (setpriority(PRIO_PROCESS, PRIO_PROCESS, -15)  == -1)
    {
      perror("Error setting process priority. Exiting...");
      exit(EXIT_FAILURE);
    }
  }
#endif  /* __HAVE_TURBO__ */

  /* Calculating CIDR for destination address. */
  cidr_ptr = config_cidr(o->bits, o->ip.daddr);
  
  /* "pid" is zero only for child processes */
  if (pid)
  {
    /* Getting the local time. */
    lt = time(NULL); tm = localtime(&lt);

		/* FIXME: Why use '\b\r' at the beginning?! */
    printf("\b\r%s %s successfully launched on %s %2d%s %d %.02d:%.02d:%.02d\n",
      PACKAGE,  VERSION, months[tm->tm_mon], tm->tm_mday, getOrdinalSuffix(tm->tm_mday),
      (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
  }
  
  /* Execute if flood or while threshold greater than 0. */
  while (o->flood || o->threshold--)
  {
    /* Setting the destination IP address to RANDOM IP address. */
    if (cidr_ptr->hostid)
    {
      /* Generation RANDOM position for computed IP addresses. */
      /* FIX: No floating point! >-| */
      rand_daddr = rand() % cidr_ptr->hostid;

  		/* FIX: No addresses array needed */
	  	o->ip.daddr = htonl(cidr_ptr->__1st_addr + rand_daddr);
    }   

    /* Sending ICMP/IGMP/TCP/UDP packets. */
    if (o->ip.protocol != IPPROTO_T50)
    {
      /* Getting the correct protocol. */
      o->ip.protocol = mod_table[o->ip.protoname].protocol_id;

      /* Launching t50 module. */
      if (mod_table[o->ip.protoname].func(fd, o))
      {
        perror("Error sending packet");
        close(fd);
        exit(EXIT_FAILURE);
      }
    }
    else
    {
      /* NOTE: Using single pointer instead of calculating
               the pointers in every iteration. */               
      modules_table_t *p;

      /* Sending T50 packets. */ 
      for (p = mod_table; p->func != NULL; p++)
      {
        /* Getting the correct protocol. */
        o->ip.protocol = p->protocol_id;

        /* Launching t50 module. */
        if (p->func(fd, o))
        {
          perror("Error sending packet");
          close(fd);
          exit(EXIT_FAILURE);
        }
      }

      /* Sanitizing the threshold. */
      o->threshold -= num_modules - 1;

      /* Reseting protocol. */
      o->ip.protocol = IPPROTO_T50;
    }
  }

  /* Closing the socket. */
  close(fd);

  /* NOTE: pid is zero only for child processes. */  
  if (pid)
  {
    /* Getting the local time. */
    lt = time(NULL); tm = localtime(&lt);

		/* FIXME: Why use '\b\r' at the beginning?! */
    printf("\b\r%s %s successfully finished on %s %2d%s %d %.02d:%.02d:%.02d\n",
      PACKAGE,  VERSION, months[tm->tm_mon], tm->tm_mday, getOrdinalSuffix(tm->tm_mday),
      (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
  }
  
  return(EXIT_SUCCESS);
}
