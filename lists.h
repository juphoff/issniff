/* $Id$ */

#define CACHE_INC 16

typedef struct PList {
  struct PList *next, *prev;
  ADDR_T daddr, saddr;
  PORT_T dport, sport;		/* dport redundant, but saves some arg passes */
  UCHAR *data;
  UINT dlen, pkts, timeout;
  time_t stime;
} PList;

typedef struct Ports {
  int port;
  PList *next;
} Ports;

#define END_NODE(NODE, PORT, REASON) \
  pdump((NODE), (REASON)); \
  if ((NODE)->next) \
    (NODE)->next->prev = (NODE)->prev; \
  if ((NODE)->prev) \
    (NODE)->prev->next = (NODE)->next; \
  else \
    (ports + (PORT))->next = (NODE)->next; \
  (NODE)->next = cache->next; \
  cache->next = (NODE); \
  ++cache_size; \
  --curr_conn;
