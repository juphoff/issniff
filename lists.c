/* $Id$ */

#include "globals.h"
#include "filter.h"

/*
 * Local variables.
 */
static sigset_t storeset;

static void
expand_cache (void)
{
  UCHAR *blk = NULL;
  int i;
  PList *cnode = cache;

  /* No signal-blocking. */
  if (!(blk = (UCHAR *)malloc ((sizeof (PList) + sizeof (UDATA) * maxdata) *
			       cache_increment))) {
    perror ("** malloc"); 	/* Not fatal, though recovery is untested! */
  } else {
    for (i = 0; i < cache_increment; i++, blk += sizeof (UDATA) * maxdata) {
      cnode->next = (PList *)blk;
      cnode->next->data = (UDATA *)(blk += sizeof (PList));
      cnode = cnode->next;
    }
    /* cnode->next = NULL; */ /* Ummm? */
    cache_max += cache_increment;
    cache_size += cache_increment;
  }
}

void add_node (PORT_T DPORT, ADDR_T DADDR, PORT_T SPORT, ADDR_T SADDR, 
	       int HAS_SYN, UCHAR *BUF, IPhdr *IPH, TCPhdr *TCPH, 
	       int SHIFT, int LENGTH) {
  PList *new = NULL;
  if (!cache_size) {
    expand_cache ();
  }
  if (cache_size) {
    sigprocmask (SIG_SETMASK, &blockset, &storeset);
    new = cache->next;
    cache->next = cache->next->next;
    --cache_size;
    ++curr_conn;
    new->prev = NULL;
    new->daddr = DADDR;
    new->saddr = SADDR;
    new->dport = DPORT;
    new->sport = SPORT;
    new->pkts[pkt_to] = 1;
    new->pkts[pkt_from] = 0;
    new->dlen = 0;
    new->caught_syn = HAS_SYN;
    memset (new->data, 0, sizeof (UDATA) * maxdata);
    time (&new->stime);		/* Need hack for file reads with timestamps */
    new->timeout = new->stime;
    if (!ports[DPORT].next) {
      new->next = NULL;
      ports[DPORT].next = new;
    } else {
      ports[DPORT].next->prev = new;
      new->next = ports[DPORT].next;
      ports[DPORT].next = new;
    }
    sigprocmask (SIG_SETMASK, &storeset, NULL);
    add_data (new, BUF, IPH, TCPH, SHIFT, LENGTH);
  } else {
    mention (DPORT, DADDR, SPORT, SADDR, "No memory; NOT MONITORING");
  }
}

void add_data(PList *node, UCHAR *buf, IPhdr *iph, TCPhdr *tcph, int toshift,
	      int thelength) {
  int i = 0;
  int blen = ((thelength < ntohs (IPLEN(iph))) ? thelength : ntohs (IPLEN(iph))) - IPHLEN(iph) - DOFF(tcph);
  int todo = (node->dlen + blen > maxdata) ? maxdata - node->dlen : blen;

  while (i < todo) {
    node->data[node->dlen + i] = (UDATA)(buf[i]) << toshift;
    i++;
  }
  node->dlen += todo;

  if (node->dlen == maxdata) {
    ++stats[s_maxdata];
    END_NODE (node, node->dport, "MAXDATA");
  } else {
    time (&node->timeout);	/* Need to handle files with timestamps */
  }
}

void END_NODE(PList *NODE, PORT_T PORT, const char *REASON) { \
  dump_node (NODE, REASON);
  sigprocmask (SIG_SETMASK, &blockset, &storeset);
  if (NODE->next) {
    NODE->next->prev = NODE->prev;
  }
  if (NODE->prev) {
    NODE->prev->next = NODE->next;
  } else {
    ports[PORT].next = NODE->next;
  }
  NODE->next = cache->next;
  cache->next = NODE;
  ++cache_size;
  --curr_conn;
  sigprocmask (SIG_SETMASK, &storeset, NULL);
}
