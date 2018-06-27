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
#include <locale.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h> /* POSIX.1 compliant */
#ifndef NDEBUG
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
#include <t50_shuffle.h>
#include <t50_help.h>

static pid_t pid = -1;      /* -1 is a trick used when __HAVE_TURBO__ isn't defined. */
static sig_atomic_t child_is_dead = 0; /* Used to kill child process if necessary. */

_NOINLINE static void               initialize ( const struct config_options * );
_NOINLINE static modules_table_t   *selectProtocol ( const struct config_options *const, int * );

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

/**
 * Main function launches all T50 modules
 */
int main ( int argc, char *argv[] )
{
  struct config_options *co;
  struct cidr           *cidr_ptr;
  modules_table_t       *ptbl;
  int                   proto;
  time_t                lt;

  // default C (US) locale...
  setlocale ( LC_ALL, "C" );

  show_version();

  /* Parse_command_line returns ONLY if there are no errors.
     This must be called before testing user privileges. */
  co = parse_command_line ( argv );

  /* User must have root privileges to run T50, unless --help or --version options are found on command line. */
  if ( getuid() )
    fatal_error ( "User must have root privilege to run." );

  initialize ( co );
  create_socket();

  /* Calculates CIDR for destination address. */
  if ( ! ( cidr_ptr = config_cidr ( co ) ) )
    return EXIT_FAILURE;

#ifdef  __HAVE_TURBO__

  /* Creates the forked process if turbo is turned on. */
  if ( co->turbo )
  {
    /* if it's necessary to fork a new process... */
    if ( ( co->ip.protocol == IPPROTO_T50 && co->threshold > number_of_modules ) ||
         ( co->ip.protocol != IPPROTO_T50 && co->threshold > 1 ) )
    {
      threshold_t new_threshold;

      if ( ( pid = fork() ) == -1 )
        fatal_error ( "Cannot create child process"
#ifndef NDEBUG
                      ": \"%s\".\nExiting..", strerror ( errno )
#endif
                    );

      /* Divide the process iterations in main loop between both processes. */
      new_threshold = co->threshold / 2;

      /* Don't let parent process get the extra packet if threshold is odd. */
      if ( !IS_CHILD_PID ( pid ) )
        new_threshold += ( co->threshold & 1 );

      /* Updates threshold for this process. */
      co->threshold = new_threshold;
    }
  }

#endif  /* __HAVE_TURBO__ */

  /* Setting the priority to both parent and child process. */
  if ( setpriority ( PRIO_PROCESS, PRIO_PROCESS, -15 )  == -1 )
    fatal_error ( "Cannot set process priority"
#ifndef NDEBUG
                  ": \"%s\".\nExiting..", strerror ( errno )
#endif
                );

  /* Show launch info only for parent process. */
  if ( !IS_CHILD_PID ( pid ) && !co->quiet )
  {
    /* Getting the local time. */
    lt = time ( NULL );

    printf ( INFO " " PACKAGE_NAME " successfully launched at %s\n",
             ctime( &lt ) );
  }

  // SRANDOM is here because each process has its own
  // random seed. Notice this is called after fork().
  SRANDOM();

  // Indices used for IPPROTO_T50 shuffling.
  build_indices();

  /* Preallocate packet buffer. */
  alloc_packet ( INITIAL_PACKET_SIZE );

  /* Selects the initial protocol to use. */
  if ( co->ip.protocol != IPPROTO_T50 )
    ptbl = selectProtocol ( co, &proto );
  else
  {
    proto = co->ip.protocol;
    shuffle ( indices, number_of_modules );
    ptbl = &mod_table[get_index ( co )];
  }

  /* MAIN LOOP */
  // OBS: flood means non stop injection.
  //      threshold is the number of packets to inject.
  while ( co->flood || co->threshold )
  {
    /* Will hold the actual packet size after module function call. */
    uint32_t size;

    /* Set the destination IP address to RANDOM IP address. */
    co->ip.daddr = cidr_ptr->__1st_addr;

    if ( cidr_ptr->hostid )
      // cidr_ptr->hostid has bit 0=0. The remainder is always less
      // then the divisor, so we need to add 1.
      co->ip.daddr += RANDOM() % ( cidr_ptr->hostid + 1 );

    co->ip.daddr = htonl ( co->ip.daddr );

    /* Finally, calls the 'module' function to build the packet. */
    co->ip.protocol = ptbl->protocol_id;
    ptbl->func ( co, &size );

#ifndef NDEBUG

    /* I'll use this to fine tune the alloc_packet() function, someday! */
    if ( size > ETH_DATA_LEN )
      fprintf ( stderr, DEBUG " Protocol %s packet size (%u bytes) exceed max. Ethernet packet data length!\n",
                ptbl->name, size );

#endif

    /* Try to send the packet. */
    if ( unlikely ( !send_packet ( packet, size, co ) ) )
#ifndef NDEBUG
      error ( "Packet for protocol %s (%zu bytes long) not sent", ptbl->name, size );

    /* continue trying to send other packets on debug mode! */
#else
      fatal_error ( "Unspecified error sending a packet" );
#endif

    /* If protocol is 'T50', then get the next true protocol. */
    if ( proto == IPPROTO_T50 )
      ptbl = &mod_table[get_index ( co )];

    /* Decrement the threshold only if not flooding! */
    if ( !co->flood )
      co->threshold--;
  }

  /* Show termination message only for parent process. */
  if ( !IS_CHILD_PID ( pid ) )
  {
#ifdef __HAVE_TURBO__

    // NOTE: Notice that for a single process pid will be -1! */
    if ( pid > 0 )
    {
      // Don't do this if child process is already dead!
      if ( !child_is_dead )
      {
        /* Wait 5 seconds for the child to end... */
        alarm ( WAIT_FOR_CHILD_TIMEOUT );
#ifndef NDEBUG
        fputs ( INFO " Waiting for child process to end...\n", stderr );
#endif

        /* NOTE: SIGALRM will kill the child process if necessary! */
        wait ( NULL );
        child_is_dead = 1;

        alarm ( 0 );
      }
    }

#endif

    /* Finally we close the raw socket. */
    close_socket();

    if ( !co->quiet )
    {
      lt = time ( NULL );

      printf ( INFO " " PACKAGE_NAME " successfully finished at %s\n",
               ctime ( &lt ) );
    }
  }

  /* Everything went well. Exit. */
  return 0;
}
#pragma GCC diagnostic pop

/* This function handles signal interrupts. */
static void signal_handler ( int signal )
{
  /* NOTE: SIGALRM and SIGCHLD will happen only in parent process! */
  switch ( signal )
  {
    case SIGALRM:
      if ( !IS_CHILD_PID ( pid ) )
        kill ( pid, SIGKILL );

      return;

    case SIGCHLD:
      child_is_dead = 1;
      return;

    // FIXME: Possibly I have to deal with SIGTERM as well...
    //case SIGTERM:
    //  /* TODO */
  }

  close_socket();   // AS_SAFE!

  /* The shell documentation (bash) specifies that a process,
     when exits because a signal, must return 128+signal#. */
  exit ( 128 + signal );
}

void initialize ( const struct config_options *co )
{
  static struct sigaction sa = { .sa_handler = signal_handler, .sa_flags = SA_RESTART };
  static sigset_t sigset;

  /* Blocks SIGTSTP avoiding ^Z behavior. */
  sigemptyset ( &sigset );
  sigaddset ( &sigset, SIGTSTP );
#ifdef NDEBUG
  sigaddset ( &sigset, SIGTRAP );
#endif
  sigprocmask ( SIG_BLOCK, &sigset, NULL );

  /* --- Initialize signal handlers --- */
  /* All these signals are handled by our handle. */
  sigfillset( &sigset );
  sa.sa_mask = sigset;
  sigaction ( SIGPIPE, &sa, NULL );
  sigaction ( SIGINT,  &sa, NULL );
  sigaction ( SIGCHLD, &sa, NULL );
  sigaction ( SIGALRM, &sa, NULL );
  //sigaction(SIGTERM, &sa, NULL );

  /* --- To simplify things, make sure stdout is unbuffered
         (otherwise, it's line buffered). --- */
  fflush ( stdout );
  setvbuf ( stdout, NULL, _IONBF, 0 );

  /* --- Show some messages. */
  if ( !co->quiet )
  {
    if ( co->flood )
      fputs ( INFO " Entering flood mode...", stdout );
    else
      printf ( INFO " Sending %u packets...\n", co->threshold );

#ifdef __HAVE_TURBO__

    if ( co->turbo )
      puts ( INFO " Turbo mode active..." );

#endif

    if ( co->bits )
      puts ( INFO " Performing stress testing..." );

    puts ( INFO " Hit Ctrl+C to stop..." );
  }
}

/* Selects the initial protocol based on the configuration. */
modules_table_t *selectProtocol ( const struct config_options *const co, int *proto )
{
  modules_table_t *ptbl;

  ptbl = mod_table;

  if ( ( *proto = co->ip.protocol ) != IPPROTO_T50 )
    ptbl += co->ip.protoname;

  return ptbl;
}
