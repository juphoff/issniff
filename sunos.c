/* $Id$ */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/time.h>
#include "sunos.h"
#include "sniff.h"
#include <netinet/if_ether.h>
#include <net/nit_if.h>

/*
 * Local variables.
 */
static int iface;
static int linkhdr_len;
static struct ifreq ifr;
/* SunOS interface type prefixes and their link-level packet header sizes. */
static struct {
  const char *type;
  int hdr_len;
} if_types[] = {
  { "le", sizeof (struct ether_header) },
  { NULL }			/* Any others for SunOS?  Not soon! */
};

/*
 * Local function prototypes.
 */
static char *if_detect (void);

/*
 * Stuff not prototyped in SunOS (that I can find).
 */
extern int ioctl (int, int, caddr_t);
extern int socket(int, int, int);
extern void bcopy (char *, char *, int);
extern void bzero (char *, int);

/*
 * Signal handler.
 */
void
if_close (int sig)
{
  close (iface);
  fprintf (stderr, "Interface %s shut down; signal %d.\n", ifr.ifr_name, sig);
  exit (0);
}

/* Consolidate. */
char *
if_getname (void)
{
  return ifr.ifr_name;
}

/* Consolidate. */
int
if_setname (const char *interface)
{
  int i = -1;

  while (if_types[++i].type) {
    if (!strncmp (if_types[i].type, interface, strlen (if_types[i].type))) {
      linkhdr_len = if_types[i].hdr_len;
      strncpy (ifr.ifr_name, interface, IFNAMSIZ);
      return 0;
    }
  }
  return -1;
}

void
if_open (int nolocal)
{
  struct strioctl si;
  struct timeval to;
  u_int if_bufsiz = IF_BUFSIZ;
  u_long if_flags = NI_PROMISC;
#if 0
  u_long snaplen = 0;
#endif

  if (!*ifr.ifr_name) {
    char *interface = if_detect ();

    if (!interface) {
      fprintf (stderr, "Cannot auto-detect a default interface.  Odd, that\n");
      exit (1);
    }
    assert (if_setname (interface) == 0);
  }
  if ((iface = open (NIT_DEV, O_RDONLY)) < 0) {
    perror ("open");
    exit (errno);
  }
  if (ioctl (iface, I_SRDOPT, (char *)RMSGD) < 0) {
    perror ("ioctl (I_SRDOPT)");
    exit (errno);
  }
  si.ic_timout = INFTIM;

  if (ioctl (iface, I_PUSH, "nbuf") < 0) {
    perror ("ioctl (I_PUSH)");
    exit (errno);
  }
  to.tv_sec = 1;
  to.tv_usec = 0;
  si.ic_cmd = NIOCSTIME;
  si.ic_len = sizeof (to);
  si.ic_dp = (char *)&to;

  if (ioctl (iface, I_STR, (char *)&si) < 0) {
    perror ("ioctl (I_STR: NIOCSTIME)");
    exit (errno);
  }
  si.ic_cmd = NIOCSCHUNK;
  si.ic_len = sizeof (if_bufsiz);
  si.ic_dp = (char *)&if_bufsiz;

  if (ioctl (iface, I_STR, (char *)&si) < 0) {
    perror ("ioctl (I_STR: NIOCSCHUNK)");
    exit (errno);
  }
  /* No check here to see if it's up; I'll just let the ioctl() fail for now. */
  si.ic_cmd = NIOCBIND;
  si.ic_len = sizeof (ifr);
  si.ic_dp = (char *)&ifr;

  if (ioctl (iface, I_STR, (char *)&si) < 0) {
    perror ("ioctl (I_STR: NIOCBIND)");
    exit (errno);
  }
  si.ic_cmd = NIOCSFLAGS;
  si.ic_len = sizeof (if_flags);
  si.ic_dp = (char *)&if_flags;

  if (ioctl (iface, I_STR, (char *)&si) < 0) {
    perror ("ioctl (I_STR: NIOCSFLAGS)");
    exit (errno);
  }
#if 0
  si.ic_cmd = NIOCSSNAP;
  si.ic_len = sizeof (snaplen);
  si.ic_dp = (char *)&snaplen;
  if (ioctl (iface, I_STR, (char *)&si) < 0) {
    perror ("ioctl (I_STR: NIOCSSNAP)");
    exit (errno);
  }
#endif
  if (ioctl (iface, I_FLUSH, (char *)FLUSHR) < 0) {
    perror ("ioctl (I_FLUSH)");
    exit (errno);
  }
  fprintf (stderr, "Listening on %s.\n", ifr.ifr_name);
  fprintf (stderr, "Warning: locally-originating packets not monitored!\n\n");
}

/* Consolidate. */
static char *
if_detect (void)
{
  char ifb[IF_DETECT_BUFSIZ];
  int dumsock;
  struct ifconf ifs;

  if ((dumsock = socket (AF_INET, SOCK_RAW, 0)) == -1) {
    perror ("socket");
    exit (errno);
  }
  ifs.ifc_len = sizeof (ifb);
  memset (ifs.ifc_buf = (caddr_t)&ifb, 0, sizeof (ifb));

  if (ioctl (dumsock, SIOCGIFCONF, (char *)&ifs) < 0) {
    perror ("ioctl (SIOCGIFCONF)");
    close (dumsock);
    return NULL;
  } else {
    int i = -1;

    while (if_types[++i].type) {
      struct ifreq *ifrp = ifs.ifc_req;

      while (*ifrp->ifr_name) {
	if (!strncmp (if_types[i].type, ifrp->ifr_name,
		      strlen (if_types[i].type))) {
	  close (dumsock);
	  return ifrp->ifr_name;
	}
	++ifrp;
      }
    }
    close (dumsock);
    return NULL;
  }
}

/*
 * This needs work!
 */
void
if_read (void)
{
  int cc;
  struct nit_bufhdr *hdrp;
  UCHAR abuf[IF_BUFSIZ], rbuf[IF_BUFSIZ];
  UCHAR *bp, *bufstop, *cp;

  /* Need to use nit_pf to leave all but TCP/IP out of the read() stream. */
  while ((cc = read (iface, rbuf, IF_BUFSIZ)) >= 0) {
    bp = rbuf;
    bufstop = rbuf + cc;

    while (bp < bufstop) {
      cp = bp;
      hdrp = (struct nit_bufhdr *)cp;
      cp += sizeof (struct nit_bufhdr);
      bp += hdrp->nhb_totlen;
      bcopy ((char *)cp + linkhdr_len, (char *)abuf,
	     (int)(hdrp->nhb_msglen - linkhdr_len));
      filter (abuf);
    }
  }
}
