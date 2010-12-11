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

extern void add_node (PORT_T, ADDR_T, PORT_T, ADDR_T, int, UCHAR *, IPhdr *, TCPhdr *, int, int);
extern void mention (PORT_T, ADDR_T, PORT_T, ADDR_T, const char *);
extern void add_data (PList *, UCHAR *, IPhdr *, TCPhdr *, int, int);
extern void END_NODE (PList *, PORT_T, const char *);
