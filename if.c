#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "if.h"
#include IFOSHEADER

#define IF_DETECT_BUFSIZ 1024	/* Big enough for ~25 interfaces + slop. */

/*
 * Function protoypes.
 */
char *if_getname (void);
int if_setname (const char *);

/*
 * Functions.
 */

char *
if_detect (int passed_iface)
{
  char ifb[IF_DETECT_BUFSIZ];
  int iface = passed_iface;
  struct ifconf ifs;

  if (iface == USE_TEMP_SOCK) {
    /* Socket type doesn't matter here.... */
    if ((iface = socket (AF_INET, SOCK_RAW, 0)) < 0) {
      perror ("socket");
      return NULL;
    }
  }
  ifs.ifc_len = sizeof (ifb);
  memset (ifs.ifc_buf = (caddr_t)&ifb, 0, sizeof (ifb));

  if (ioctl (iface, SIOCGIFCONF, (char *)&ifs) < 0) {
    perror ("ioctl (SIOCGIFCONF)");

    if (passed_iface == USE_TEMP_SOCK) {
      close (iface);
    }
    return NULL;
  } else {
    int i = -1;

    if (passed_iface == USE_TEMP_SOCK) {
      close (iface);
    }
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

char *
if_getname (void)
{
  return ifr.ifr_name;
}

int
if_setname (const char *interface)
{
  int i = -1;

  while (if_types[++i].type) {
    if (!strncmp (if_types[i].type, interface, strlen (if_types[i].type))) {
      linkhdr_len = if_types[i].hdr_len;
      strncpy (ifr.ifr_name, interface, IFNAMSIZ);
      return SUCCESSFUL;
    }
  }
  return UNSUCCESSFUL;
}
