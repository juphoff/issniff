/* $Id$ */

/*
 * Primary data structures.
 */
/* Connection data. */
typedef struct PList {
  struct PList *next, *prev;
  ADDR_T daddr, saddr;
  PORT_T dport, sport;		/* dport redundant, but saves some arg passes */
  UDATA *data;			/* 2:1 byte ratio for data; gives direction. */
  UINT dlen, pkts[2];
  time_t stime, timeout;
  int caught_syn;
} PList;

typedef struct Ports {
  PORT_T port;
  int twoway;
  PList *next;
} Ports;

enum { pkt_to, pkt_from };
enum { with_syn, without_syn, first_fin };

/*
 * Major functionality is provided by these macros.
 */
#if 0
#define END_NODE(NODE, PORT, REASON) { \
  dump_node ((NODE), (REASON)); \
  sigprocmask (SIG_SETMASK, &blockset, &storeset); \
  if ((NODE)->next) { \
    (NODE)->next->prev = (NODE)->prev; \
  } \
  if ((NODE)->prev) { \
    (NODE)->prev->next = (NODE)->next; \
  } else { \
    ports[(PORT)].next = (NODE)->next; \
  } \
  (NODE)->next = cache->next; \
  cache->next = (NODE); \
  ++cache_size; \
  --curr_conn; \
  sigprocmask (SIG_SETMASK, &storeset, NULL); \
}

#define ADD_DATA(NODE, BUF, IPH, TCPH, SHIFT, THELENGTH) { \
  int i = 0; \
  int blen = (((THELENGTH) < ntohs (IPLEN((IPH)))) ? (THELENGTH) : ntohs (IPLEN((IPH)))) - IPHLEN((IPH)) - DOFF((TCPH)); \
  int todo = ((NODE)->dlen + blen > maxdata) ? maxdata - (NODE)->dlen : blen; \
  while (i < todo) { \
    (NODE)->data[(NODE)->dlen + i] = (UDATA)((BUF)[i++]) << (SHIFT); \
  } \
  (NODE)->dlen += todo; \
  if ((NODE)->dlen == maxdata) { \
    ++stats[s_maxdata]; \
    END_NODE ((NODE), (NODE)->dport, "MAXDATA"); \
  } else { \
    time (&(NODE)->timeout);	/* Need to handle files with timestamps */ \
  } \
}
#endif

extern void add_node (PORT_T, ADDR_T, PORT_T, ADDR_T, int, UCHAR *, IPhdr *, TCPhdr *, int, int);
extern void mention (PORT_T, ADDR_T, PORT_T, ADDR_T, const char *);
extern void add_data (PList *, UCHAR *, IPhdr *, TCPhdr *, int, int);
extern void END_NODE (PList *, PORT_T, const char *);
