/* $Id$ */

#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "memory.h"
#include "sniff.h"

#ifdef __linux__
# include "linux.h"
#endif

#include "lists.h"

static int cache_max = 0;
static int cache_size = 0;
static int curr_conn = 0;
static int hiport = 0;
static int maxdata = IS_MAXDATA;

static struct PList *find_node (PORT_T, ADDR_T, PORT_T, ADDR_T);
static void add_data (struct PList *, const u_char *, int, PORT_T);
static void add_node (PORT_T, ADDR_T, PORT_T, ADDR_T);
static void end_node (struct PList *, PORT_T);
static void expand_cache (void);
static void init_cache (void);
static void pdump (struct PList *, PORT_T);
static void sniff (void);

static void
init_cache (void)
{
  cache = (struct PList *)xmalloc (sizeof (struct PList));
  cache->next = NULL;
}

static void
expand_cache (void)
{
  int i;
  u_char *data_block = NULL;
  struct PList *cp = cache;
  void *list_block = NULL;

  /*
   * Perhaps set the increment to be based on how many entries can fit
   * into one physical page of memory?
   */
  list_block = xmalloc (sizeof (struct PList) * CACHE_INC);
  data_block = (u_char *)xmalloc (sizeof (u_char) * CACHE_INC * maxdata);

  for (i = 0; i < CACHE_INC; i++) {
    cp->next = (struct PList *)(list_block + (sizeof (struct PList) * i));
    cp->next->data = data_block + (sizeof (u_char) * i * maxdata);
    cp = cp->next;
  }
  cache_max += CACHE_INC;
  cache_size += CACHE_INC;
}

/* Will grow as I find things to talk about.... */
static void
dump_state (int sig)
{
  int i;

  signal (SIGHUP, dump_state);
  fprintf (stderr, "\n* Max cache size: %d\n", cache_max);
  fprintf (stderr, "* Current cache size: %d\n", cache_size);
  fprintf (stderr, "* Currently gathering data on %d connections\n", curr_conn);
  fprintf (stderr, "* Max data size: %d\n", maxdata);
  fprintf (stderr, "* Listening on ports:");

  for (i = 0; i <= hiport; i++)
    if (ports[i].port)
      fprintf (stderr, " %d", i);

  fprintf (stderr, "\n\n");
  return;
}

int
main (int argc, char **argv)
{
  if (argc > 1) {
    int i, iargc, thisport;
    
    /* Will switch to getopt() later.... */
    if (!strcmp (argv[1], "-d")) {
      maxdata = atoi (argv[2]);
      iargc = 3;
    } else
      iargc = 1;

    for (i = iargc; i < argc; i++) {
      thisport = atoi (argv[i]);
      hiport = thisport > hiport ? thisport : hiport;
    }
    /* Yes, wasting some memory for the sake of speed. */
    ports = (struct Ports *)xmalloc (sizeof (struct Ports) * (hiport + 1));
    memset (ports, 0, sizeof (struct Ports) * (hiport + 1)); /* Ummm. */

    for (i = iargc; i < argc; i++)
      ++ports[atoi (argv[i])].port;
  } else {
    fprintf (stderr, "Must specify some ports!\n");
    return 1;
  }
  open_interface ();
  signal (SIGINT, close_interface);
  signal (SIGQUIT, close_interface);
  signal (SIGTERM, close_interface);
  init_cache ();
  expand_cache ();		/* Just so we're ready for packet #1. */
  signal (SIGHUP, dump_state);	/* Must come *after* data init's. */
  sniff ();
  close_interface (0);		/* Should not be reached. */
  return 0;
}

static void
sniff (void)
{
  char buf[IS_BUFSIZ + 1];
  int dport, sport;
  ADDR_T daddr, saddr;		/* Portability problem (later).... */
  struct PList *node = NULL;
  IPhdr *iph;
  TCPhdr *tcph;
  
  for (;;)
    if (read (iface, buf, IS_BUFSIZ) >= 0) {
      /* Should probably look at ETHhhdr and pitch non-IP. */
      iph = (IPhdr *)(buf + sizeof (ETHhdr));

      if (IPPROT(iph) != TCPPROT) /* Only looking at TCP right now. */
	continue;

      tcph = (TCPhdr *)(buf + sizeof (ETHhdr) + IPHLEN(iph));

      if ((dport = ntohs (DPORT(tcph))) > hiport || !(ports + dport)->port)
	continue;

      if (!(node = find_node (dport, daddr = DADDR(iph),
			      sport = ntohs (SPORT(tcph)),
			      saddr = SADDR(iph)))) {
	if (SYN(tcph)) {
	  add_node (dport, daddr, sport, saddr);
	}
      } else {
	++(node->pkts);

	if (FINRST(tcph)) {
	  end_node (node, dport);
	} else {
	  add_data (node,
		    (const u_char *)(buf + sizeof (ETHhdr) + IPHLEN(iph) +
				     DOFF(tcph)),
		    ntohs (IPLEN(iph)) - IPHLEN(iph) - DOFF(tcph), dport);
	}
      }
    }
}

/*
 * Should be made a macro call.
 */
static void
end_node (struct PList *node, PORT_T dport)
{
  pdump (node, dport);

  if (node->next)
    node->next->prev = node->prev;

  if (node->prev)
    node->prev->next = node->next;
  else
    (ports + dport)->next = node->next;

  node->next = cache->next;
  cache->next = node;
  ++cache_size;
  --curr_conn;
}
    
/*
 * Should be made a macro call.
 */
static void
add_data (struct PList *node, const u_char *buf, int plen, PORT_T dport)
{
  int tocopy;

  tocopy = (node->dlen + plen > maxdata) ? maxdata - node->dlen : plen;
  memcpy ((u_char *)&node->data[node->dlen], buf, tocopy);
  node->dlen += tocopy;
  if (node->dlen == maxdata)
    end_node (node, dport);
}

/*
 * Should be made a macro call.
 */
static void
add_node (PORT_T dport, ADDR_T daddr, PORT_T sport, ADDR_T saddr)
{
  struct PList *new = NULL;

  if (!cache->next)
    expand_cache ();

  /* Gotta watch this. */
  new = cache->next;
  cache->next = cache->next->next;
  --cache_size;
  ++curr_conn;

  new->prev = NULL;
  new->daddr = daddr;
  new->saddr = saddr;
  new->sport = sport;
  new->pkts = 1;
  new->dlen = 0;
  time (&(new->stime));		/* Store start time. */

  if (!(ports + dport)->next) {
    new->next = NULL;
    (ports + dport)->next = new;
  } else {
    (ports + dport)->next->prev = new;
    new->next = (ports + dport)->next;
    (ports + dport)->next = new;
  }
}

static struct PList *
find_node (PORT_T dport, ADDR_T daddr, PORT_T sport, ADDR_T saddr)
{
  struct PList *p = (ports + dport)->next;

  while (p) {
    if ((p->sport == sport) && (p->saddr == saddr) && (p->daddr == daddr))
      break;

    p = p->next;
  }
  return p;
}

static void
pdump (struct PList *node, PORT_T dport)
{
  u_char lastc = 0;
  struct in_addr ia;
  time_t now = time (NULL);
  char *timp = ctime (&node->stime);

  printf ("------------------------------------------------------------------------\n");
  timp[strlen (timp) - 1] = 0;
  printf ("Time: %s ", timp);
  printf ("to %s", ctime (&now));
  ia.s_addr = SADDR(node);
  printf ("Path: %s:%d -> ", inet_ntoa (ia), node->sport);
  ia.s_addr = DADDR(node);
  printf ("%s:%d\n", inet_ntoa (ia), dport);
  printf ("Stat: %d packets, %d bytes ", node->pkts, node->dlen);
  printf ("[%s]\n\n", node->dlen == maxdata ? "DATA LIMIT" : "FIN/RST");

  while (node->dlen-- > 0) {
    if (*node->data < 32) {
      switch (*node->data) {
      case '\0':
	if ((lastc == '\r') || (lastc == '\n') || (lastc =='\0'))
	  break;
      case '\r':
      case '\n':
	printf ("\n");
	break;
      default:
	printf ("(^%c)", (*node->data + 64));
	break;
      }
    } else {
      if (isprint (*node->data))
	printf ("%c", *node->data);
      else
	printf ("(%d)", *node->data);
    }
    lastc = *node->data++;
  }
  printf ("\n------------------------------------------------------------------------\n");
}
