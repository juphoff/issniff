/* $Id$ */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "linux.h"
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
    char *interface = if_detect (iface);

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
