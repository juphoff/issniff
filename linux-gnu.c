/* $Id$ */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "linux-gnu.h"
#include "sniff.h"
#include "if.h"

/*
 * Local variables.
 */
static int iface;

/*
 * Signal handler.
 */
void
if_close_net (int sig)
{
  ifr.ifr_flags &= ~IFF_PROMISC;

  if (ioctl (iface, SIOCSIFFLAGS, &ifr) < 0) {
    perror ("ioctl (SIOCSIFFLAGS)");
    exit (errno);
  }
  close (iface);
  fprintf (stderr, "Interface %s shut down; signal %d.\n", ifr.ifr_name, sig);

  if (sig) {
    exit (0);
  }
}

/*
 * BPF.
 */
#ifdef HAVE_LINUX_FILTER_H_
void
if_open_net (int nolocal)
{
}
#else
/*
 * Pre-BPF.
 */
void
if_open_net (int nolocal)
{
				/* This is obsolete as of 2.1.x. */
  if ((iface = socket (AF_INET, SOCK_PACKET,
		       ntohs (nolocal ? ETH_P_IP : ETH_P_ALL))) < 0) {
    perror ("socket");
    exit (errno);
  }
  if (!*ifr.ifr_name) {
    char *interface = if_detect (iface);

    if (!interface) {
      fprintf (stderr, "Cannot auto-detect a default interface.  Odd, that.\n");
      exit (1);
    }
    assert (if_setname (interface) == SUCCESSFUL);
  }
  if (ioctl (iface, SIOCGIFFLAGS, &ifr) < 0) {
    perror ("ioctl (SIOCGIFFLAGS)");
    exit (errno);
  }
  if (!(ifr.ifr_flags & IFF_UP)) {
    fprintf (stderr, "Interface %s not up.\n", ifr.ifr_name);
    exit (1);
  }
  ifr.ifr_flags |= IFF_PROMISC;

  if (ioctl (iface, SIOCSIFFLAGS, &ifr) < 0) {
    perror ("ioctl (SIOCSIFFLAGS)");
    exit (errno);
  }
  fprintf (stderr, "Version %s listening on %s.\n\n", IS_VERSION, ifr.ifr_name);

  if (nolocal) {
    fprintf (stderr, "Warning: locally-originated packets not monitored!\n\n");
  }
}
#endif

/*
 * Mainly here for portability since other OS's buffer the sniffing.
 */
void
if_read_ip_net (void (*filter) (UCHAR *, int))
{
  int bytes;
  UCHAR buf[IF_BUFSIZ];

  for (;;) {
    if ((bytes = read (iface, buf, IF_BUFSIZ)) >= 0) {
      if (!linkhdr_len || ETHTYPE ((ETHhdr *)buf) == IPTYPE) { /* Fix me. */
	filter (&buf[linkhdr_len], bytes - linkhdr_len);
      }
    }
  }
}

#if 0
void
if_read_ip_raw (void (*filter) (UCHAR *, int))
{
  int bytes;
  UCHAR buf[IF_BUFSIZ];

  for (;;) {
    if ((bytes = read (iface, buf, IF_BUFSIZ)) >= 0) {
      if (!linkhdr_len || ETHTYPE ((ETHhdr *)buf) == IPTYPE) { /* Fix me. */
	filter (buf, bytes);
      }
    }
  }
}
#endif
