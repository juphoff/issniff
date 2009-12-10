/* $Id$ */

#include "globals.h"
#include "filter.h"

/*
 * Local variables.
 */
static sigset_t storeset;	/* Used in lists.h macros. */

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

void ADD_NODE (PORT_T DPORT, ADDR_T DADDR, PORT_T SPORT, ADDR_T SADDR, 
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
    new->daddr = (DADDR);
    new->saddr = (SADDR);
    new->dport = (DPORT);
    new->sport = (SPORT);
    new->pkts[pkt_to] = 1;
    new->pkts[pkt_from] = 0;
    new->dlen = 0;
    new->caught_syn = (HAS_SYN);
    memset (new->data, 0, sizeof (UDATA) * maxdata);
    time (&new->stime);		/* Need hack for file reads with timestamps */
    new->timeout = new->stime;
    if (!ports[(DPORT)].next) {
      new->next = NULL;
      ports[(DPORT)].next = new;
    } else {
      ports[(DPORT)].next->prev = new;
      new->next = ports[(DPORT)].next;
      ports[(DPORT)].next = new;
    }
    sigprocmask (SIG_SETMASK, &storeset, NULL);
    ADD_DATA (new, (BUF), (IPH), (TCPH), (SHIFT), (LENGTH));
  } else {
    mention (DPORT, DADDR, SPORT, SADDR, "No memory; NOT MONITORING");
  }
}
