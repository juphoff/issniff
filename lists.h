/* $Id$ */

#define CACHE_INC 16

struct PList {
  struct PList *next, *prev;
  ADDR_T saddr, daddr;
  PORT_T sport;
  u_char *data;
  u_int dlen;
  u_int pkts;
  time_t stime;
};
  
static struct Ports {
  int port;
  struct PList *next;
} *ports;

static struct PList *cache;
