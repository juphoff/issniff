/* $Id$ */

typedef struct PList {
  struct PList *next, *prev;
  ADDR_T daddr, saddr;
  PORT_T dport, sport;		/* dport redundant, but saves some arg passes */
  UCHAR *data;
  UINT dlen, pkts;
  time_t stime, timeout;
} PList;

typedef struct Ports {
  int port;
  PList *next;
} Ports;

#define END_NODE(NODE, PORT, REASON) { \
  dump_node((NODE), (REASON)); \
  if ((NODE)->next) \
    (NODE)->next->prev = (NODE)->prev; \
  if ((NODE)->prev) \
    (NODE)->prev->next = (NODE)->next; \
  else \
    (ports + (PORT))->next = (NODE)->next; \
  (NODE)->next = cache->next; \
  cache->next = (NODE); \
  ++cache_size; \
  --curr_conn; \
}

#define ADD_DATA(NODE, BUF, IPH, TCPH) { \
  int blen = ntohs (IPLEN((IPH))) - IPHLEN((IPH)) - DOFF((TCPH)); \
  int todo = ((NODE)->dlen + blen > maxdata) ? maxdata - (NODE)->dlen : blen; \
  memcpy ((UCHAR *)&(NODE)->data[(NODE)->dlen], (BUF), todo); \
  (NODE)->dlen += todo; \
  if ((NODE)->dlen == maxdata) { \
    END_NODE ((NODE), (NODE)->dport, "MAXDATA"); \
  } else { \
    time (&(NODE)->timeout); \
  } \
}

#define ADD_NODE(DPORT, DADDR, SPORT, SADDR) { \
  PList *new; \
  if (!cache->next) \
    expand_cache (); \
  new = cache->next; \
  cache->next = cache->next->next; \
  --cache_size; \
  ++curr_conn; \
  new->prev = NULL; \
  new->daddr = (DADDR); \
  new->saddr = (SADDR); \
  new->dport = (DPORT); \
  new->sport = (SPORT); \
  new->pkts = 1; \
  new->dlen = 0; \
  time (&new->stime); \
  new->timeout = new->stime; \
  if (!(ports + (DPORT))->next) { \
    new->next = NULL; \
    (ports + (DPORT))->next = new; \
  } else { \
    (ports + (DPORT))->next->prev = new; \
    new->next = (ports + (DPORT))->next; \
    (ports + (DPORT))->next = new; \
  } \
}

#define MENTION(DPORT, DADDR, SPORT, SADDR, MSG) { \
  struct in_addr ia; \
  ia.s_addr = (SADDR); \
  fprintf (stderr, "*  %s: %s:%d -> ", (MSG), inet_ntoa (ia), (SPORT)); \
  ia.s_addr = (DADDR); \
  fprintf (stderr, "%s:%d\n", inet_ntoa (ia), (DPORT)); \
}
