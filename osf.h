/* $Id$ */

#include <errno.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/*
 * General definitions.
 */
#define IF_BUFSIZ 8192
#define OS_NOLOCAL 0
#define USING_BPF 1

/*
 * IP protocol header definitions.
 */
#define IPPROT(X) ((X)->ip_p)
#define DADDR(X) ((X)->ip_dst.s_addr)
#define SADDR(X) ((X)->ip_src.s_addr)
#define IPHLEN(X) (((X)->ip_vhl & 0x0f) * 4) /* Blah. */
#define IPLEN(X) ((X)->ip_len)
#define TCPPROT IPPROTO_TCP

/*
 * TCP protocol header definitions
 */
#define SPORT(X) ((X)->th_sport)
#define DPORT(X) ((X)->th_dport)
#define DOFF(X) (((X)->th_xoff >> 4) * 4) /* Blah again. */
#define SYN(X) ((X)->th_flags & TH_SYN)
#define FIN(X) ((X)->th_flags & TH_FIN)
#define RST(X) ((X)->th_flags & TH_RST)
#define FINRST(X) ((X)->th_flags & (TH_FIN | TH_RST))

/*
 * Data types.
 */
typedef u_int ADDR_T;
typedef u_short PORT_T;
typedef u_char UCHAR;
typedef unsigned short int UDATA;
typedef u_int UINT;
typedef struct ip IPhdr;
typedef struct tcphdr TCPhdr;
