/* $Id$ */

#include <ctype.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "sniff.h"

#ifdef __linux__
# include "linux.h"
#endif

#include "lists.h"

static int cache_increment = CACHE_INC;
static int cache_management = 0;
static int cache_max = 0;
static int cache_size = 0;
static int curr_conn = 0;
static int hiport = 0;
static int maxdata = IS_MAXDATA;
static int squash_output = 0;	/* Squash (compress) sequential newlines. */
static int timeout = IS_TIMEOUT; /* Eventually CL overrideable. */
static int verbose = 0;		/* Running commentary of new connections. */
static PList *cache;
static Ports *ports;

static void expand_cache (void);
static void dump_conns (int);
static void dump_node (PList *, const char *);
static void dump_state (int);
static void shrink_cache (int);
static void sniff (void);
static PList *find_node (PORT_T, ADDR_T, PORT_T, ADDR_T);

/*
 * Signal handler.
 */
static void
dump_state (int sig)
{
  int i;

  signal (SIGUSR1, dump_state);
  fprintf (stderr, "\n\
** Current state:\n\
*  Interface: %s\n\
*  Max cache entries: %d\n\
*  Current cache entries: %d\n\
*  Cache increment: %d\n\
*  Cache management (unsupported): %s\n\
*  Active connections: %d\n\
*  Max data size (bytes): %d\n\
*  Idle timeout (seconds): %d\n\
*  Squashed output: %s\n\
*  Verbose mode: %s\n\
*  Monitoring ports:",
	   get_interface (),
	   cache_max,
	   cache_size,
	   cache_increment,
	   YN (cache_management),
	   curr_conn,
	   maxdata,
	   timeout,
	   YN (squash_output),
	   YN (verbose));

  for (i = 0; i <= hiport; i++) {
    if (ports[i].port) {
      fprintf (stderr, " %d", i);
    }
  }
  fputs ("\n\n", stderr);
}

/*
 * Signal handler.
 */
static void
dump_conns (int sig)
{
  char *timep;
  int i;
  PList *node;

  signal (SIGUSR2, dump_conns);
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

static void
expand_cache (void)
{
  int i;
  UCHAR *dblk, *lblk;
  PList *node = cache;

  /* Consolidate?  Perhaps also make malloc() failures non-fatal here? */
  if (!(lblk = (UCHAR *)malloc (sizeof (PList) * cache_increment))) {
    perror ("malloc");
    exit (errno);
  }
  if (!(dblk = (UCHAR *)malloc (sizeof (UCHAR) * cache_increment * maxdata))) {
    perror ("malloc");
    exit (errno);
  }
  for (i = 0; i < cache_increment; i++) {
    node->next = (PList *)(lblk + sizeof (PList) * i);
    node->next->data = dblk + sizeof (UCHAR) * i * maxdata;
    node = node->next;
  }
  cache_max += cache_increment;
  cache_size += cache_increment;
}

/*
 * Only used when cache management requested.
 */
static void
shrink_cache (int tozap)
{
  /* Stub. */
  return;
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

static void
sniff (void)
{
  ADDR_T daddr, saddr;
  PORT_T dport, sport;
  UCHAR buf[IS_BUFSIZ];
  IPhdr *iph;
  TCPhdr *tcph;
  PList *node;
  
  for (;;) {
    if (read (iface, buf, IS_BUFSIZ) >= 0) {
      /* Should probably look at ETHhhdr and pitch non-IP. */
      iph = (IPhdr *)(buf + sizeof (ETHhdr));

      if (IPPROT(iph) != TCPPROT) { /* Only looking at TCP right now. */
	continue;
      }
      tcph = (TCPhdr *)(buf + sizeof (ETHhdr) + IPHLEN(iph));

      if ((dport = ntohs (DPORT(tcph))) > hiport || !(ports + dport)->port) {
	continue;
      }
      if (!(node = find_node (dport, daddr = DADDR(iph),
			      sport = ntohs (SPORT(tcph)),
			      saddr = SADDR(iph)))) {
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
	  ADD_DATA (node, buf + sizeof (ETHhdr) + IPHLEN(iph) + DOFF(tcph),
		    iph, tcph);
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
    int i, thisport;
    
    while ((opt = getopt (argc, argv, "c:d:i:t:msv")) != -1) {
      switch (opt) {
      case 'c':
	cache_increment = atoi (optarg) ? atoi (optarg) : CACHE_INC;
	break;
      case 'd':
	maxdata = atoi (optarg) ? atoi (optarg) : IS_MAXDATA;
	break;
      case 'i':
	set_interface (optarg);
	break;
      case 'm':
	cache_management = 1;
	break;
      case 's':
	squash_output = 1;
	break;
      case 't':
	timeout = atoi (optarg) ? atoi (optarg) : IS_TIMEOUT;
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
      thisport = atoi (argv[i]);
      hiport = thisport > hiport ? thisport : hiport;
    }
    /* Yes, wasting some memory for the sake of speed. */
    if (!(ports = (Ports *)malloc (sizeof (Ports) * (hiport + 1)))) {
      perror ("malloc");
      exit (errno);
    }
    memset (ports, 0, sizeof (Ports) * (hiport + 1));

    for (i = optind; i < argc; i++) {
      ++ports[atoi (argv[i])].port;
    }
  } else {
    fputs ("Must specify some ports!\n", stderr);
    return 1;
  }
  open_interface ();
  signal (SIGHUP, close_interface);
  signal (SIGINT, close_interface);
  signal (SIGQUIT, close_interface);
  signal (SIGTERM, close_interface);
  /* Initialize cache. */
  if (!(cache = (PList *)malloc (sizeof (PList)))) {
    perror ("malloc");
    exit (errno);
  }
  cache->next = NULL;
  expand_cache ();		/* Just so we're ready for packet #1. */
  signal (SIGUSR1, dump_state);	/* Must come *after* data init's. */
  signal (SIGUSR2, dump_conns);	/* Ditto. */
  sniff ();			/* Main loop is here. */
  close_interface (0);		/* Should not be reached. */
  return 0;
}

/*
 * A real mess.  Will probably be moved to children.
 */
static void
dump_node (PList *node, const char *reason)
{
  struct in_addr ia;
  UCHAR lastc = 0;
  UCHAR *data = node->data;
  char *timep = ctime (&node->stime);
  time_t now = time (NULL);

  puts ("------------------------------------------------------------------------");
  timep[strlen (timep) - 1] = 0; /* Zap newline. */
  printf ("Time: %s ", timep);
  printf ("to %s", ctime (&now)); /* Two calls to printf() for a reason! */
  ia.s_addr = node->saddr;
  printf ("Path: %s:%d -> ", inet_ntoa (ia), node->sport);
  ia.s_addr = node->daddr;
  printf ("%s:%d\n", inet_ntoa (ia), node->dport);
  printf ("Stat: %d packets, %d bytes [%s]\n\n", node->pkts, node->dlen,
	  reason);

  while (node->dlen-- > 0) {
    if (*data < 32) {
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
    } else {
      if (isprint (*data)) {
	putchar (*data);
      } else {
	printf ("<%d>", *data);
      }
    }
    lastc = *data++;
  }
  puts ("\n------------------------------------------------------------------------");
}
