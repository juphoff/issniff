/* $Id$ */

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include "globals.h"
#include "sniff.h"
#include "shm.h"
#include "filter.h"
#include "misc.h"

/*
 * Global variables.
 */
char if_name[MAXNAMLEN];	/* Remove from global list. */
PORT_T hiport = 0;
int all_conns = 0;
int cache_increment = CACHE_INC;
int cache_max = 0;
int cache_size = 0;
int curr_conn = 0;
/* int hiport = 0; */
int maxdata = IS_MAXDATA;
int of_methods = to_stdout;
int timeout = IS_TIMEOUT;
int verbose = 0;
int stats[] = { 0, 0, 0, 0 };
sigset_t blockset;
FILE *of_p = NULL;
Ports *ports;
PList *cache;

#if defined(DEBUG) && defined(USING_BPF)
int non_tcp = 0;
#endif /* DEBUG && USING_BPF */

/*
 * Local variables.
 */
static char of_name[MAXNAMLEN];
static int addr_matching = 0;
static int colorfrom = FROM_COLOR;
static int colorize = 0;
static int colorto = TO_COLOR;
static int nolocal = OS_NOLOCAL;
static int squash_output = 0;

#ifdef SUPPORT_TCPDUMP
static int file_read = 0;
#endif

/*
 * Local function prototypes.
 */
static void dump_conns (int);
static void show_conns (int);
static void show_state (int);

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
static void (*if_read) (void (*) (UCHAR *, int)) = if_read_ip_net;

/*
 * Signal handler.
 */
static void
dump_conns (int sig)
{
  PORT_T i;
  PList *node;

  for (i = 0; i <= hiport; i++) {
    if ((node = ports[i].next)) {
      while (node) {
	DUMP_NODE (node, "SIGNAL");
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
  PORT_T i;
  PList *node;

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
  PORT_T i;

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
*  Monitoring connctions detected 'late': %s\n\
*  Squashed output: %s\n\
*  Verbose mode: %s\n\
*  Ted Turner mode (colorization): %s\n\
*  Connection stats:\n\
*    FIN terminated: %d\n\
*    RST terminated: %d\n\
*    Exceeded data size: %d\n\
*    Exceeded timeout:   %d\n",
	   IS_VERSION,
	   if_getname (),
	   curr_conn,
	   cache_size,
	   cache_max,
	   cache_increment,
	   maxdata,
	   timeout,
	   YN (nolocal),
	   YN (all_conns),
	   YN (squash_output),
	   YN (verbose),
	   YN (colorize),
	   stats[s_fin],
	   stats[s_rst],
	   stats[s_maxdata],
	   stats[s_timeout]);

  if (all_conns)
    fprintf (stderr, "*    Detected 'late':    %d\n", stats[s_late]);

  fputs ("*  Monitoring ports:", stderr);

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

int
main (int argc, char **argv)
{
  struct sigaction sigact;

  if (argc > 1) {
    char opt;
    int i;
    while ((opt = getopt (argc, argv, "F:O:T:c:d:i:o:t:w:Canrsv")) != -1) {
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
#if 0
	/* Still working on/thinking about other filters.... */
	filter = sf_filter;
	if_read = if_read_ip_raw;
#endif
	strncpy (of_name, optarg, MAXNAMLEN);

	if (!(of_p = fopen (of_name, "a"))) {
	  perror ("Cannot open output file");
	  exit (errno);
	}
	break;
      case 'r':
	filter = shm_filter;
	shm_setup ();
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
#ifdef SUPPORT_TCPDUMP
      case 'w':			/* For 'tcpdump -w' files. */
	/* Need error checking for conflicting options, e.g. -i */
	file_read = 1;
	if_open = if_open_pcap;
	if_close = if_close_pcap;
	if_read = if_read_ip_pcap;
	strncpy (if_name, optarg, MAXNAMLEN);
	break;
#else
      case 'w':
	fputs ("'tcpdump -w' save-files not supported under this OS.\n",
	       stderr);
	return 1;
#endif	
      default:
	fputs ("Usage: issniff [options] [+]port [[+]port ...]\n", stderr);
	return 1;
      }
    }
    for (i = optind; i < argc; i++) {
      if (!strncmp (argv[i], "+addr", 5)) {
	break;
      } else {
	PORT_T thisport =
	  (PORT_T)(argv[i][0] == '+' ? atoi (&argv[i][1]) : atoi (argv[i]));
	hiport = thisport > hiport ? thisport : hiport;
      }
    }
    /* Yes, wasting some (lots at times) memory for the sake of speed. */
    if (!(ports = (Ports *)malloc (sizeof (Ports) * (hiport + 1)))) {
      perror ("malloc");
      exit (errno);
    }
    memset (ports, 0, sizeof (Ports) * (hiport + 1));
    /* Second time through arg. lists.  Clean this up. */
    for (i = optind; i < argc; i++) {
      if (!strncmp (argv[i], "+addr", 5)) {
	addr_matching = i;
	break;
      } else {
	PORT_T thisport =
	  (PORT_T)(argv[i][0] == '+' ? atoi (&argv[i][1]) : atoi (argv[i]));
	ports[thisport].port = 1;
	ports[thisport].twoway = argv[i][0] == '+' ? 1 : 0;
/* 	ports[thisport].next = (PList *)NULL; */ /* JAU: From sol port...why? */
      }
    }
  } else {
    fputs ("Must specify some ports and/or addresses!\n", stderr);
    return 1;
  }
  if (sigfillset (&blockset) < 0) {
    perror ("sigfillset");
    exit (errno);
  }
  /* Need sanity checks on sigaction() return values. */
  sigact.sa_mask = blockset;
#ifndef SIG_STUPIDITY
# define SIG_STUPIDITY 0
#endif
  sigact.sa_flags = SIG_STUPIDITY;
  sigact.sa_handler = *if_close;
  if_open (nolocal);

  if ((sigaction (SIGQUIT, &sigact, NULL) < 0) ||
      (sigaction (SIGTERM, &sigact, NULL) < 0)) {
    perror ("sigaction (QUIT|TERM)");
    exit (errno);
  }
  /* Initialize cache. */
  if (!(cache = (PList *)malloc (sizeof (PList)))) {
    perror ("malloc");
    exit (errno);
  }
  cache->next = NULL;
  EXPAND_CACHE;			/* Get ready for first packet. */
  sigact.sa_handler = dump_conns;

  if ((sigaction (SIGINT, &sigact, NULL) < 0) ||
      (sigaction (SIGHUP, &sigact, NULL) < 0)) {
    int err = errno;
    perror ("sigaction (INT|HUP)");
    if_close (0);
    exit (err);
  }
  sigact.sa_handler = show_state;

  if (sigaction (SIGUSR1, &sigact, NULL) < 0) {
    int err = errno;
    perror ("sigaction (USR1)");
    if_close (0);
    exit (err);
  }
  sigact.sa_handler = show_conns;

  if (sigaction (SIGUSR2, &sigact, NULL) < 0) {
    int err = errno;
    perror ("sigaction (USR2)");
    if_close (0);
    exit (err);
  }
  if_read (*filter);		/* Main loop. */
  if_close (0);			/* Not reached. */
  return -1;
}

/*
 * Will probably be moved to children and talked to via shared memory.
 *
 * Output of two-way monitoring when not colorizing looks ugly; needs work.
 */
void
dump_node (const PList *node, const char *reason, FILE *fh)
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
