/* $Id$ */

#include <errno.h>
#include <sys/types.h>
#include <netinet/in_systm.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/bufmod.h>

/*
 * General definitions.
 */
#define IF_BUFSIZ SB_DFLT_CHUNK
#define IF_BUF_TIMER 1		/* Flush /dev/nit buffer every # seconds. */
#if 0
#define NET_DEV "/dev/le"
#endif
#define OS_NOLOCAL 0		/* Correct for Solaris? */
#if 1
#define USING_BPF 0		/* Later.... */
#endif
#define SIG_STUPIDITY SA_RESTART

/*
 * IP protocol header definitions.
 */
#define IPPROT(X) ((X)->ip_p)
#define DADDR(X) ((X)->ip_dst.s_addr)
#define SADDR(X) ((X)->ip_src.s_addr)
#define IPHLEN(X) ((X)->ip_hl * 4)
#define IPLEN(X) ((X)->ip_len)

/*
 * TCP protocol header definitions
 */
#define SPORT(X) ((X)->th_sport)
#define DPORT(X) ((X)->th_dport)
#define DOFF(X) ((X)->th_off * 4)
#define SYN(X) ((X)->th_flags & TH_SYN)
#define FIN(X) ((X)->th_flags & TH_FIN)
#define RST(X) ((X)->th_flags & TH_RST)
#define FINRST(X) ((X)->th_flags & (TH_FIN | TH_RST))

/*
 * Temporary Ethernet shit.
 */
#define ETHTYPE(X) ((X)->ether_type)
#define IPTYPE ETHERTYPE_IP

/*
 * Data types.
 */
typedef u_long ADDR_T;
typedef u_short PORT_T;
typedef u_char UCHAR;
typedef unsigned short int UDATA;
typedef u_int UINT;
typedef struct ip IPhdr;
typedef struct tcphdr TCPhdr;

typedef struct ether_header ETHhdr;

/*
 * Stuff "missing" in Solaris.
 */
/* extern char *optarg; */
/* extern int optind; */
