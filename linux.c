/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "sniff.h"
#include "linux.h"

static struct ifreq ifr;

/*
 * Signal handler.
 */
void
close_interface (int sig)
{
  ifr.ifr_flags &= ~IFF_PROMISC;

  if (ioctl (iface, SIOCSIFFLAGS, &ifr) == -1) {
    perror ("ioctl (SIOCSIFFLAGS)");
    exit (errno);
  }
  fprintf (stderr, "Interface %s shut down; signal %d.\n", ifr.ifr_name, sig);
  exit (0);
}

char *
get_interface (void)
{
  return ifr.ifr_name;
}

void
set_interface (const char *interface)
{
  strncpy (ifr.ifr_name, interface, IFNAMSIZ);
}

void
open_interface (void)
{
  if ((iface = socket (AF_INET, SOCK_PACKET, SOCKPROT)) == -1) {
    perror ("socket");
    exit (errno);
  }
  if (!*ifr.ifr_name)
    set_interface (DEFAULT_INTERFACE);

  if (ioctl (iface, SIOCGIFFLAGS, &ifr) == -1) {
    perror ("ioctl (SIOCGIFFLAGS)");
    exit (errno);
  }
  ifr.ifr_flags |= IFF_PROMISC;

  if (ioctl (iface, SIOCSIFFLAGS, &ifr) == -1) {
    perror ("ioctl (SIOCSIFFLAGS)");
    exit (errno);
  }
  fprintf (stderr, "Listening on %s.\n\n", ifr.ifr_name);
}
