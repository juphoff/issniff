/* $Id$ */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include OSVER".h"
#include "lists.h"

/*
 * Global variables.
 */
enum { s_finrst, s_maxdata, s_timeout, s_late };
enum { to_stdout = 1, to_file = 2 };
extern int all_conns;
extern int cache_increment;
extern int cache_max;
extern int cache_size;
extern int curr_conn;
extern int hiport;
extern int maxdata;
extern int of_methods;
extern int timeout;
extern int verbose;
extern int stats[];
extern sigset_t blockset;
extern FILE *of_p;
extern Ports *ports;
extern PList *cache;

#if defined(DEBUG) && defined(USING_BPF)
extern int non_tcp;
#endif /* DEBUG && USING_BPF */
