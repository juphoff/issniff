/* $Id$ */

#include "globals.h"
#include "filter.h"

/*
 * Local variables.
 */
static sigset_t storeset;	/* Used in lists.h macros. */

/*
 * Local function prototypes.
 */
static PList *find_node (PORT_T, ADDR_T, PORT_T, ADDR_T);

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
void
rt_filter (UCHAR *buf, int len)
{
  enum { data_to = 0, data_from = 8 };
  IPhdr *iph = (IPhdr *)buf;

#if defined(DEBUG) || !defined(USING_BPF)
  if (IPPROT (iph) != IPPROTO_TCP) { /* Only looking at TCP/IP right now. */
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
		    data_from, len);

	  if (FIN (tcph)) {
	    ++stats[s_fin];
	    END_NODE (node, sport, "<-FIN");
	  } else if (RST (tcph)) {
	    ++stats[s_rst];
	    END_NODE (node, sport, "<-RST");
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
	    mention (dport, daddr, sport, saddr, "New connection");
	  }
	  ADD_NODE (dport, daddr, sport, saddr, with_syn,
		    &buf[IPHLEN (iph) + DOFF (tcph)], iph, tcph, data_to, len);
	} else if (all_conns && !FINRST (tcph)) {
	  /*
	   * Bug: if this is the ACK between the two FIN's for this
	   * connection, we'll get an erroneous (two-packet) connection
	   * track.  Need to save state here somehow...blah.
	   */
	  if (verbose) {
	    mention (dport, daddr, sport, saddr, "Detected 'late'");
	  }
	  ADD_NODE (dport, daddr, sport, saddr, without_syn,
		    &buf[IPHLEN (iph) + DOFF (tcph)], iph, tcph, data_to, len);
	  ++stats[s_late];
	}
      } else {
	++node->pkts[pkt_to];
	ADD_DATA (node, &buf[IPHLEN (iph) + DOFF (tcph)], iph, tcph, data_to,
		  len);

	if (FIN (tcph)) {
	  ++stats[s_fin];
	  END_NODE (node, dport, "FIN->");
	} else if (RST (tcph)) {
	  ++stats[s_rst];
	  END_NODE (node, dport, "RST->");
	}
      }
    }
#if defined(DEBUG) || !defined(USING_BPF)
  }
#endif /* DEBUG || !USING_BPF */
}

/*
 * "Shared-memory" filter.  *stub*
 */
void
shm_filter (UCHAR *buf, int len)
{
  return;
}

/*
 * "Save-file" filter.  Thoughts in progress....
 */
#if 0
void
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
  if (IPPROT (iph) != IPPROTO_TCP) {
    return;
  } else {
    printf ("about to write\n");
    if (write (of_fd, &buf, len) != len) {
      perror ("write");
    }
  }
}
#endif

/*
 * Does double duty as a node-finder and as a timeout routine.  Used by
 * rt_filter().
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
    /* Timeout handling. */
    if (timeout && node->timeout && (now - node->timeout > timeout)) {
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
