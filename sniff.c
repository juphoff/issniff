/* $Id$ */

#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#ifdef __linux__
# include <getopt.h>
# include "linux.h"
#endif

#ifdef __sun__
# include <unistd.h>
# include "sunos.h"
#endif

#include "sniff.h"
#include "lists.h"

static int cache_increment = CACHE_INC;
static int cache_max = 0;
static int cache_size = 0;
static int curr_conn = 0;
static int hiport = 0;
static int maxdata = IS_MAXDATA;
static int squash_output = 0;
static int timeout = IS_TIMEOUT;
static int verbose = 0;
static PList *cache;
static Ports *ports;

static void dump_conns (int);
static void dump_node (const PList *, const char *);
static void dump_state (int);
static void show_conns (int);
static PList *find_node (PORT_T, ADDR_T, PORT_T, ADDR_T);

/*
 * Signal handler.
 */
static void
dump_conns (int sig)
{
  int i;
  PList *node;

  if (sig == SIGHUP) {
    signal (SIGHUP, dump_conns);
  }
  for (i = 0; i <= hiport; i++) {
    if ((node = (ports + i)->next)) {
      while (node) {
	dump_node (node, "SIGNAL");
	node = node->next;
      }
    }
  }
  if (sig == SIGHUP) {
    return;
  }
  close_interface (sig);
}

/*
 * Signal handler.
 */
static void
dump_state (int sig)
{
  int i;

  signal (sig, dump_state);
  fprintf (stderr, "\n\
** Current state:\n\
*  Interface: %s\n\
*  Active connections: %d\n\
*  Current cache entries: %d\n\
*  Max cache entries: %d\n\
*  Cache increment: %d\n\
*  Max data size (bytes): %d\n\
*  Idle timeout (seconds): %d\n\
*  Squashed output: %s\n\
*  Verbose mode: %s\n\
*  Monitoring ports:",
	   get_interface (),
	   curr_conn,
	   cache_size,
	   cache_max,
	   cache_increment,
	   maxdata,
	   timeout,
	   YN (squash_output),
	   YN (verbose));

  for (i = 0; i <= hiport; i++) {
    if (ports[i].port) {
      if (ports[i].twoway) {
	fprintf (stderr, " +%d", i);
      } else {
	fprintf (stderr, " %d", i);
      }
    }
  }
  fputs ("\n\n", stderr);
}

/*
 * Signal handler.
 */
static void
show_conns (int sig)
{
  char *timep;
  int i;
  PList *node;

  signal (sig, show_conns);
  fputs ("\n** Active connections:\n", stderr);

  for (i = 0; i <= hiport; i++) {
    if ((node = (ports + i)->next)) {
      while (node) {
	timep = ctime (&node->stime);
	timep[strlen (timep) - 1] = 0; /* Zap newline */
	MENTION(node->dport, node->daddr, node->sport, node->saddr, timep);
	node = node->next;
      }
    }
  }
  fputc ('\n', stderr);
}

/*
 * Does double duty as a node-finder and as a timeout routine.
 */
static PList *
find_node (PORT_T dport, ADDR_T daddr, PORT_T sport, ADDR_T saddr)
{
  PList *node = (ports + dport)->next;
  time_t now = time (NULL);

  while (node) {
    /* What's the optimal order for these, I wonder? */
    if ((node->sport == sport) && (node->saddr == saddr) &&
	(node->daddr == daddr)) {
      break;
    }
    /* Timeout stanza. */
    if (timeout && (now - node->timeout > timeout)) {
      PList *nnode = node->next;
      END_NODE (node, dport, "TIMEOUT");
      node = nnode;
    } else {
      node = node->next;
    }
  }
  return node;
}

/*
 * Finds the packets we're interested in and does fun things with them.
 */
void
filter (UCHAR *buf)
{
  IPhdr *iph = (IPhdr *)buf;

  if (IPPROT(iph) != TCPPROT) { /* Only looking at TCP right now. */
    return;
  } else {
    TCPhdr *tcph = (TCPhdr *)(buf + IPHLEN(iph));
    ADDR_T dport = ntohs (DPORT (tcph));

    if (dport > hiport || !(ports + dport)->port) {
      return;
    } else {
      PORT_T sport = ntohs (SPORT (tcph));
      ADDR_T daddr = DADDR (iph), saddr = SADDR (iph);
      PList *node = find_node (dport, daddr, sport, saddr);

      if (!node) {
	if (SYN(tcph)) {
	  ADD_NODE (dport, daddr, sport, saddr);

	  if (verbose) {
	    MENTION (dport, daddr, sport, saddr, "New connection");
	  }
	}
      } else {
	++node->pkts;

	if (FINRST(tcph)) {
	  END_NODE (node, dport, "FIN/RST");
	} else {
	  ADD_DATA (node, buf + IPHLEN(iph) + DOFF(tcph), iph, tcph);
	}
      }
    }
  }
}

int
main (int argc, char **argv)
{
  if (argc > 1) {
    char opt;
    int i;
    
    while ((opt = getopt (argc, argv, "c:d:i:t:sv")) != -1) {
      switch (opt) {
      case 'c':
	cache_increment = CHKOPT (CACHE_INC);
	break;
      case 'd':
	maxdata = CHKOPT (IS_MAXDATA);
	break;
      case 'i':
	set_interface (optarg);
	break;
      case 's':
	squash_output = 1;
	break;
      case 't':
	timeout = CHKOPT (IS_TIMEOUT);
	break;
      case 'v':
	verbose = 1;
	break;
      default:
	fputs ("Usage: issniff [options] port [port...]\n", stderr);
	return 1;
      }
    }
    for (i = optind; i < argc; i++) {
      int thisport = argv[i][0] == '+' ? atoi (&argv[i][1]) : atoi (argv[i]);
      hiport = thisport > hiport ? thisport : hiport;
    }
    /* Yes, wasting some memory for the sake of speed. */
    if (!(ports = (Ports *)malloc (sizeof (Ports) * (hiport + 1)))) {
      perror ("malloc");
      exit (errno);
    }
    memset (ports, 0, sizeof (Ports) * (hiport + 1));

    for (i = optind; i < argc; i++) {
      int thisport = argv[i][0] == '+' ? atoi (&argv[i][1]) : atoi (argv[i]);
      ports[thisport].port = 1;
      ports[thisport].twoway = argv[i][0] == '+' ? 1 : 0;
    }
  } else {
    fputs ("Must specify some ports!\n", stderr);
    return 1;
  }
  open_interface ();
  signal (SIGQUIT, close_interface);
  signal (SIGTERM, close_interface);
  /* Initialize cache. */
  if (!(cache = (PList *)malloc (sizeof (PList)))) {
    perror ("malloc");
    exit (errno);
  }
  cache->next = NULL;
  EXPAND_CACHE;			/* Get ready for first packet. */
  signal (SIGINT, dump_conns);
  signal (SIGHUP, dump_conns);
  signal (SIGUSR1, dump_state);
  signal (SIGUSR2, show_conns);
  ifread ();			/* Main loop. */
  close_interface (0);		/* Not reached. */
  return 0;
}

/*
 * Will probably be moved to children.
 */
static void
dump_node (const PList *node, const char *reason)
{
  struct in_addr ia;
  UCHAR lastc = 0;
  UCHAR *data = node->data;
  UINT dlen = node->dlen;
  char *timep = ctime (&node->stime);
  time_t now = time (NULL);

  puts ("========================================================================");
  timep[strlen (timep) - 1] = 0; /* Zap newline. */
  printf ("Time: %s ", timep);
  printf ("to %s", ctime (&now)); /* Two calls to printf() for a reason! */
  ia.s_addr = node->saddr;
  printf ("Path: %s:%d -> ", inet_ntoa (ia), node->sport);
  ia.s_addr = node->daddr;
  printf ("%s:%d\n", inet_ntoa (ia), node->dport);
  printf ("Stat: %d packets, %d bytes [%s]\n", node->pkts, dlen, reason);
  puts ("------------------------------------------------------------------------");

  while (dlen-- > 0) {
    if (*data >= 127) {
      printf ("<%d>", *data);
    } else if (*data >= 32) {
      putchar (*data);
    } else {
      switch (*data) {
      case '\0':
	if ((lastc == '\r') || (lastc == '\n') || (lastc =='\0')) {
	  break;
	}
      case '\r':
      case '\n':
	if (!squash_output || !((lastc == '\r') || (lastc == '\n'))) {
	  putchar ('\n');
	}
	break;
      case '\t':
	putchar ('\t');
	break;
      default:
	printf ("<^%c>", (*data + 64));
	break;
      }
    }
    lastc = *data++;
  }
  puts ("\n========================================================================");
}
