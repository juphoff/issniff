/* $Id$ */

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

static int iface;
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
  if (!*ifr.ifr_name) {
    set_interface (DEFAULT_INTERFACE);
  }
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

/*
 * I DON'T like this approach.  Blasted SunOS madness....
 */
void
ifread (void)
{
  UCHAR buf[IF_BUFSIZ];

  for (;;) {
    if (read (iface, buf, IF_BUFSIZ) >= 0) {
      filter (buf + sizeof (struct ethhdr));
    }
  }
}
