/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "sniff.h"
#include "linux.h"

static struct ifreq ifr;

void
open_interface (void)
{
  if ((iface = socket (AF_INET, SOCK_PACKET, SOCKPROT)) == -1) {
    perror ("socket");
    exit (errno);
  }
  strcpy (ifr.ifr_name, DEFAULT_INTERFACE);

  if (ioctl (iface, SIOCGIFFLAGS, &ifr) == -1) {
    perror ("ioctl (SIOCGIFFLAGS)");
    exit (errno);
  }
  ifr.ifr_flags |= IFF_PROMISC;

  if (ioctl (iface, SIOCSIFFLAGS, &ifr) == -1) {
    perror ("ioctl (SIOCSIFFLAGS)");
    exit (errno);
  }
  fprintf (stderr, "Listening on %s.\n\n", DEFAULT_INTERFACE);
}

void
close_interface (int sig)
{
  ifr.ifr_flags &= ~IFF_PROMISC;

  if (ioctl (iface, SIOCSIFFLAGS, &ifr) == -1) {
    perror ("ioctl (SIOCSIFFLAGS)");
    exit (errno);
  }
  fprintf (stderr, "Interface %s shut down.\n", DEFAULT_INTERFACE);
  exit (0);
}
