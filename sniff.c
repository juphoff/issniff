/* $Id$ */

#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include OSVER".h"
#include "sniff.h"
#include "lists.h"

/*
 * Local variables.
 */
static char of_name[NAME_MAX];
enum { to_stdout = 1, to_file = 2 };
enum { s_finrst, s_maxdata, s_timeout };
static int all_conns = 0;	/* New: doesn't work right yet. */
static int cache_increment = CACHE_INC;
static int cache_max = 0;
static int cache_size = 0;
static int colorfrom = FROM_COLOR;
static int colorize = 0;
static int colorto = TO_COLOR;
static int curr_conn = 0;
static int hiport = 0;
static int maxdata = IS_MAXDATA;
static int nolocal = OS_NOLOCAL;
static int of_methods = to_stdout;
static int squash_output = 0;
static int timeout = IS_TIMEOUT;
static int verbose = 0;
static int stats[] = { 0, 0, 0 };
static FILE *of_p = NULL;
static Ports *ports;
static PList *cache;

#if defined(DEBUG) && defined(USING_BPF)
static int non_tcp = 0;
#endif /* DEBUG && USING_BPF */
  
/*
 * Local function prototypes.
 */
static void dump_conns (int);
static void dump_node (const PList *, const char *);
static void dump_node_out (const PList *, const char *, FILE *);
static void rt_filter (UCHAR *, int);
#if 0
static void sf_filter (UCHAR *, int);
#endif
static void show_conns (int);
static void show_state (int);
static PList *find_node (PORT_T, ADDR_T, PORT_T, ADDR_T);

/*
 * Misc. local macros.
 */
#define CHKOPT(FALLBACK) (atoi (optarg) ? atoi (optarg) : (FALLBACK))
#define YN(X) ((X) ? "yes" : "no")

/*
 * Jump!
 *
 * (Default settings.)
 */
static void (*filter) (UCHAR *, int) = rt_filter;
static void (*if_close) (int) = if_close_net;
static void (*if_open) (int) = if_open_net;
static void (*if_read) (void (*) (UCHAR *, int)) = if_read_ip;

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
    if ((node = ports[i].next)) {
      while (node) {
	dump_node (node, "SIGNAL");
	node = node->next;
      }
    }
  }
  if (sig == SIGHUP) {
    return;
  }
  if_close (sig);
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
    if ((node = ports[i].next)) {
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
 * Signal handler.
 */
static void
show_state (int sig)
{
  int i;

  signal (sig, show_state);
  fprintf (stderr, "\n\
** Current state:\n\
*  Version: %s\n\
*  Interface: %s\n\
*  Active connections: %d\n\
*  Current cache entries: %d\n\
*  Max cache entries: %d\n\
*  Cache increment: %d\n\
*  Max data size (bytes): %d\n\
*  Idle timeout (seconds): %d\n\
*  Ignoring local connections/packets: %s\n\
*  Squashed output: %s\n\
*  Verbose mode: %s\n\
*  Ted Turner mode (colorization): %s\n\
*  Connection stats:\n\
*    FIN/RST terminated: %d\n\
*    Exceeded data size: %d\n\
*    Exceeded timeout:   %d\n\
*  Monitoring ports:",
	   IS_VERSION,
	   if_getname (),
	   curr_conn,
	   cache_size,
	   cache_max,
	   cache_increment,
	   maxdata,
	   timeout,
	   YN (nolocal),
	   YN (squash_output),
	   YN (verbose),
	   YN (colorize),
	   stats[s_finrst],
	   stats[s_maxdata],
	   stats[s_timeout]);

  for (i = 0; i <= hiport; i++) {
    if (ports[i].port) {
      if (ports[i].twoway) {
	fprintf (stderr, " +%d", i);
      } else {
	fprintf (stderr, " %d", i);
      }
    }
  }
#if defined(DEBUG) && defined(USING_BPF)
  fprintf (stderr,
	   "\n\n*  Number of non-TCP packets that have snuck through: %d",
	   non_tcp);
#endif /* DEBUG && USING_BPF */
  fputs ("\n\n", stderr);
}

/*
 * Does double duty as a node-finder and as a timeout routine.
 */
static PList *
find_node (PORT_T dport, ADDR_T daddr, PORT_T sport, ADDR_T saddr)
{
  time_t now = time (NULL);
  PList *node = ports[dport].next;

  while (node) {
    /* What's the optimal order for these, I wonder? */
    if ((node->sport == sport) && (node->saddr == saddr) &&
	(node->daddr == daddr)) {
      return node;
    }
    /* Timeout stanza. */
    if (timeout && (now - node->timeout > timeout)) {
      PList *nnode = node->next;
      ++stats[s_timeout];
      END_NODE (node, dport, "TIMEOUT");
      node = nnode;
    } else {
      node = node->next;
    }
  }
  return node;
}

int
main (int argc, char **argv)
{
  if (argc > 1) {
    char opt;
    int i;

    /* Add an option for 'tee'ing to a file. */
    while ((opt = getopt (argc, argv, "F:O:T:c:d:i:o:t:Cansv")) != -1) {
      switch (opt) {
      case 'C':
	colorize = 1;
	break;
      case 'F':
	colorfrom = CHKOPT (FROM_COLOR);
	colorize = 1;
	break;
      case 'T':
	colorto = CHKOPT (TO_COLOR);
	colorize = 1;
	break;
      case 'a':
	all_conns = 1;
	break;
      case 'c':
	cache_increment = CHKOPT (CACHE_INC);
	break;
      case 'd':
	maxdata = CHKOPT (IS_MAXDATA);
	break;
      case 'i':
	if (if_setname (optarg) == -1) {
	  fprintf (stderr, "Invalid/unknown interface: %s\n", optarg);
	  return 1;
	}
	break;
      case 'n':
	nolocal = 1;
	break;
	/* Under construction. */
      case 'o':
	of_methods = to_file;
      case 'O':
	of_methods |= to_file;
	/* Still working on other filters.... */
/* 	filter = sf_filter; */
/* 	if_read = if_read_ip_raw; */
	strncpy (of_name, optarg, NAME_MAX);

	if (!(of_p = fopen (of_name, "a"))) {
	  fprintf (stderr, "Cannot open output file '%s': %s\n", of_name,
		   strerror (errno));
	  exit (errno);
	}
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
	fputs ("Usage: issniff [options] [+]port [[+]port ...]\n", stderr);
	return 1;
      }
    }
    for (i = optind; i < argc; i++) {
      int thisport = argv[i][0] == '+' ? atoi (&argv[i][1]) : atoi (argv[i]);
      hiport = thisport > hiport ? thisport : hiport;
    }
    /* Yes, wasting some (lots at times) memory for the sake of speed. */
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
  if_open (nolocal);
  signal (SIGQUIT, *if_close);
  signal (SIGTERM, *if_close);
  /* Initialize cache. */
  if (!(cache = (PList *)malloc (sizeof (PList)))) {
    perror ("malloc");
    exit (errno);
  }
  cache->next = NULL;
  EXPAND_CACHE;			/* Get ready for first packet. */
  signal (SIGINT, dump_conns);
  signal (SIGHUP, dump_conns);
  signal (SIGUSR1, show_state);
  signal (SIGUSR2, show_conns);
  if_read (*filter);		/* Main loop. */
  if_close (0);			/* Not reached. */
  return -1;
}

/*
 * This is inefficient (!), but a quick hack.  Things will change....
 */ 
static void
dump_node (const PList *node, const char *reason)
{
  if (of_methods & to_file)
    dump_node_out (node, reason, of_p);

  if (of_methods & to_stdout)
    dump_node_out (node, reason, stdout);
}

/*
 * Will probably be moved to children and talked to via shared memory.
 *
 * Output of two-way monitoring when not colorizing looks ugly; needs work.
 */
static void
dump_node_out (const PList *node, const char *reason, FILE *fh)
{
  UCHAR data, lastc = 0;
  char *timep = ctime (&node->stime);
  UDATA *datp = node->data;
  int current_color = NO_COLOR;
  time_t now = time (NULL);
  UINT dlen = node->dlen;
  struct in_addr ia;

  fputs ("========================================================================\n", fh);
  timep[strlen (timep) - 1] = 0; /* Zap newline. */
  fprintf (fh, "Time: %s ", timep);
  fprintf (fh, "to %s", ctime (&now)); /* Two calls to printf() for a reason! */
  ia.s_addr = node->saddr;
  fprintf (fh, "Path: %s:%d %s ", inet_ntoa (ia), node->sport, 
	  ports[node->dport].twoway ? "<->" : "->");
  ia.s_addr = node->daddr;
  fprintf (fh, "%s:%d\n", inet_ntoa (ia), node->dport);
  fprintf (fh, "Stat: %d/%d packets (to/from), %d bytes [%s]%s\n",
	  node->pkts[pkt_to], node->pkts[pkt_from], dlen, reason,
	  node->caught_syn != with_syn ? " [LATE]" : "");
  fputs ("------------------------------------------------------------------------\n", fh);

  while (dlen-- > 0) {
    /* Ack, can't tell which way NULL bytes came from this way. */
    if (*datp > 0x00ff) {
      data = *datp++ >> 8;

      if (current_color != colorfrom) {
	if (colorize) {
	  fprintf (fh, "%c[%dm", 0x1b, current_color = colorfrom);
	} else {
	  fputs ("\n<| ", fh);
	  current_color = colorfrom;
	  lastc = '\n';
	}
      }
    } else {
      data = *datp++;

      if (current_color != colorto) {
	if (colorize) {
	  fprintf (fh, "%c[%dm", 0x1b, current_color = colorto);
	} else {
	  fputs ("\n>| ", fh);
	  current_color = colorto;
	  lastc = '\n';
	}
      }
    }
    if (data >= 127) {
      fprintf (fh, "<%d>", data);
    } else if (data >= 32) {
      putc (data, fh);
    } else {
      switch (data) {
      case '\0':
	if ((lastc == '\r') || (lastc == '\n') || (lastc =='\0')) {
	  break;
	}
      case '\r':
      case '\n':
	/* Can't tell which end a \n came from when colorizing. */
	if (!squash_output || !((lastc == '\r') || (lastc == '\n'))) {
	  if (!colorize && ports[node->dport].twoway) {
	    fputs ("\n | ", fh); /* Fix me! */
	  } else {
	    putc ('\n', fh);
	  }
	}
	break;
      case '\t':
	/* Add an option to print the control code instead of expanding it? */
	putc ('\t', fh);
	break;
      default:
	fprintf (fh, "<^%c>", (data + 64));
	break;
      }
    }
    lastc = data;
  }
  if (colorize && current_color != NO_COLOR) {
    fprintf (fh, "%c[00m", 0x1b);
  }
  fputs ("\n========================================================================\n", fh);
  fflush (fh);
}


/*
 * Various filtering routines.  Should probably be moved to a separate
 * file, perhaps to a library for use in other related app's that I'm
 * likely to hack out.
 */

/*
 * "Real-time" filter.
 *
 * Finds the packets we're interested in and does fun things with them.
 *
 * Need to check FIN/RST packets from remote end (e.g. connection
 * refused), even when not in two-way mode.
 *
 * Should probably have two copies of this: a "normal" one and one that
 * can catch connections "late."
 */
static void
rt_filter (UCHAR *buf, int len)
{
  enum { data_to = 0, data_from = 8 };
  IPhdr *iph = (IPhdr *)buf;

#if defined(DEBUG) || !defined(USING_BPF)
  if (IPPROT (iph) != TCPPROT) { /* Only looking at TCP/IP right now. */
# ifdef USING_BPF
    fprintf (stderr, "\a*** A non-TCP packet snuck through the filter!\n");
    ++non_tcp;
# endif /* USING_BPF */
    return;
  } else {
#endif /* DEBUG || !USING_BPF */
    TCPhdr *tcph = (TCPhdr *)&buf[IPHLEN (iph)];
    PORT_T dport = ntohs (DPORT (tcph)), sport = ntohs (SPORT (tcph));

    if (dport > hiport || !ports[dport].port) {
      if (sport <= hiport && ports[sport].twoway) {
	ADDR_T daddr = DADDR (iph), saddr = SADDR (iph);
	PList *node = find_node (sport, saddr, dport, daddr); /* Backwards. */

	if (node) {
	  ++node->pkts[pkt_from];
	  ADD_DATA (node, &buf[IPHLEN (iph) + DOFF (tcph)], iph, tcph,
		    data_from);

	  if (FINRST (tcph)) {
	    ++stats[s_finrst];
	    END_NODE (node, sport, "<-FIN/RST");
	  }
	}
      }
    } else {
      ADDR_T daddr = DADDR (iph), saddr = SADDR (iph);
      PList *node = find_node (dport, daddr, sport, saddr);

      if (!node) {
	/* I'll probably need to add all_conns detection both ways. */
	if (SYN (tcph)) {
	  if (verbose) {
	    MENTION (dport, daddr, sport, saddr, "New connection");
	  }
	  ADD_NODE (dport, daddr, sport, saddr, with_syn,
		    &buf[IPHLEN (iph) + DOFF (tcph)], iph, tcph, data_to);
	} else if (all_conns && !FINRST (tcph)) {
	  /*
	   * Bug: if this is the ACK between the two FIN's for this
	   * connection, we'll get an erroneous (two-packet) connection
	   * track.  Need to save state here somehow...blah.
	   */
	  if (verbose) {
	    MENTION (dport, daddr, sport, saddr, "Detected 'late'");
	  }
	  ADD_NODE (dport, daddr, sport, saddr, without_syn,
		    &buf[IPHLEN (iph) + DOFF (tcph)], iph, tcph, data_to);
	}
      } else {
	++node->pkts[pkt_to];
	ADD_DATA (node, &buf[IPHLEN (iph) + DOFF (tcph)], iph, tcph, data_to);

	if (FINRST (tcph)) {
	  ++stats[s_finrst];
	  END_NODE (node, dport, "FIN/RST->");
	}
      }
    }
#if defined(DEBUG) || !defined(USING_BPF)
  }
#endif /* DEBUG || !USING_BPF */
}

/*
 * "Save-file" filter.
 */
#if 0
static void
sf_filter (UCHAR *buf, int len)
{
  static int of_fd;
  IPhdr *iph = (IPhdr *)buf;

  if (!of_fd) {		/* Move this--don't want in loop! */
    if ((of_fd = open (of_name, O_CREAT | O_EXCL | O_WRONLY, 0600)) < 0) {
      int err = errno;

      perror ("open");
      if_close (0);
      exit (err);
    }
  }
  if (IPPROT (iph) != TCPPROT) {
    return;
  } else {
    printf ("about to write\n");
    if (write (of_fd, &buf, len) != len) {
      perror ("write");
    }
  }
}
#endif
