/* $Id$ */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include "linux.h"
#include "sniff.h"

/*
 * Local variables.
 */
static int iface;
static int linkhdr_len;
static struct ifreq ifr;

/* Linux interface type prefixes and their link-level packet header sizes. */
static struct {
  const char *type;
  int hdr_len;
} if_types[] = {
  { "eth", sizeof (struct ethhdr) },
  { "sl", 0 },
  { "lo", sizeof (struct ethhdr) },
  { "dummy", sizeof (struct ethhdr) },
  /* Still need PPP. */
  { NULL }
};

/*
 * Local function prototypes.
 */
static char *if_detect (void);

/*
 * Signal handler.
 */
void
if_close (int sig)
{
  ifr.ifr_flags &= ~IFF_PROMISC;

  if (ioctl (iface, SIOCSIFFLAGS, &ifr) == -1) {
    perror ("ioctl (SIOCSIFFLAGS)");
    exit (errno);
  }
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

/* Consolidate. */
static char *
if_detect (void)
{
  char ifb[IF_DETECT_BUFSIZ];
  struct ifconf ifs;

  ifs.ifc_len = sizeof (ifb);
  memset (ifs.ifc_buf = (caddr_t)&ifb, 0, sizeof (ifb));

  if (ioctl (iface, SIOCGIFCONF, &ifs) == -1) {
    perror ("ioctl (SIOCGIFCONF)");
    return NULL;
  } else {
    int i = -1;

    while (if_types[++i].type) {
      struct ifreq *ifrp = ifs.ifc_req;

      while (*ifrp->ifr_name) {
	if (!strncmp (if_types[i].type, ifrp->ifr_name,
		      strlen (if_types[i].type))) {
	  return ifrp->ifr_name;
	}
	++ifrp;
      }
    }
    return NULL;
  }
}

/*
 * Linux is easy.
 */
void
if_open (int nolocal)
{
  if ((iface = socket (AF_INET, SOCK_PACKET,
		       ntohs (nolocal ? ETH_P_IP : ETH_P_ALL))) == -1) {
    perror ("socket");
    exit (errno);
  }
  if (!*ifr.ifr_name) {
    char *interface = if_detect ();

    if (!interface) {
      fprintf (stderr, "Cannot auto-detect a default interface.  Odd, that.\n");
      exit (1);
    }
    assert (if_setname (interface) == 0);
  }
  if (ioctl (iface, SIOCGIFFLAGS, &ifr) == -1) {
    perror ("ioctl (SIOCGIFFLAGS)");
    exit (errno);
  }
  if (!(ifr.ifr_flags & IFF_UP)) {
    fprintf (stderr, "Interface %s not up.\n", ifr.ifr_name);
    exit (1);
  }
  ifr.ifr_flags |= IFF_PROMISC;

  if (ioctl (iface, SIOCSIFFLAGS, &ifr) == -1) {
    perror ("ioctl (SIOCSIFFLAGS)");
    exit (errno);
  }
  fprintf (stderr, "Version %s listening on %s.\n\n", IS_VERSION, ifr.ifr_name);

  if (nolocal) {
    fprintf (stderr, "Warning: locally-originating packets not monitored!\n\n");
  }
}

/*
 * Mainly here for portability since other OS's buffer the sniffing.
 */
void
if_read (void)
{
  UCHAR buf[IF_BUFSIZ];

  for (;;) {
    if (read (iface, buf, IF_BUFSIZ) >= 0) {
      filter (buf + linkhdr_len); /* Function call, over and over and over. */
    }
  }
}
