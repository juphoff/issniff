/* $Id$ */

#include <netinet/ip.h>
#include <netinet/protocols.h>
#include <netinet/tcp.h>

/*
 * General definitions.
 */
#define IF_BUFSIZ 2048
#define IF_DETECT_BUFSIZ 1024	/* Big enough for 25 interfaces + slop. */
#define SOCKPROT 0x300		/* Don't fuck with me. */
#define UCHAR u_char
#define UINT u_int
#define UDATA unsigned short int

/*
 * IP protocol header definitions.
 */
#define IPPROT(X) ((X)->protocol)
#define DADDR(X) ((X)->daddr)
#define SADDR(X) ((X)->saddr)
#define IPHLEN(X) ((X)->ihl * 4)
#define IPLEN(X) ((X)->tot_len)
#define TCPPROT IP_TCP
#define ADDR_T __u32

/*
 * TCP protocol header definitions
 */
#define SPORT(X) ((X)->th_sport)
#define DPORT(X) ((X)->th_dport)
#define DOFF(X) ((X)->th_off * 4)
#define SYN(X) ((X)->th_flags & TH_SYN)
#define FINRST(X) ((X)->th_flags & (TH_FIN | TH_RST))
#define PORT_T u_short

/*
 * Data types.
 */
typedef struct iphdr IPhdr;
typedef struct tcphdr TCPhdr;
