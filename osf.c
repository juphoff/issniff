/* $Id$ */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/pfilt.h>
#include "osf.h"
#include "sniff.h"
#include "if.h"

/*
 * Local variables.
 */
static int iface;

/* Blah. */
extern int pfopen (char *, int);

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

void
if_open (int nolocal)
{
  int one = 1;
  struct enfilter pf;
  u_short ifflags = ENPROMISC | ENBATCH | (nolocal ? 0 : ENCOPYALL);

  /* All of this mucking about with ifr not really needed under OSF/1.... */
  if (!*ifr.ifr_name) {
    char *interface = if_detect (USE_TEMP_SOCK);

    if (!interface) {
      fprintf (stderr, "Cannot auto-detect a default interface.  Odd, that.\n");
      exit (1);
    }
    assert (if_setname (interface) == 0);
  }
  if ((iface = pfopen (ifr.ifr_name, O_RDONLY)) < 0) {
    perror ("pfopen");
    exit (errno);
  }
  if (ioctl (iface, EIOCALLOWPROMISC, &one) < 0) {
    perror ("ioctl (EIOALLOWPROMISC)");
    exit (errno);
  }
  if (ioctl (iface, EIOCALLOWCOPYALL, &one) < 0) {
    perror ("ioctl (EIOALLOWCOPYALL)");
    exit (errno);
  }
  if (ioctl (iface, EIOCMBIS, &ifflags) < 0) {
    perror ("ioctl (EIOCMBIS)");
    exit (errno);
  }
  pf.enf_Priority = 32;		/* Pick a number! */
  pf.enf_FilterLen = 0;
  pf.enf_Filter[pf.enf_FilterLen++] = ENF_PUSHWORD + 11;
  pf.enf_Filter[pf.enf_FilterLen++] = ENF_PUSHLIT | ENF_AND;
  pf.enf_Filter[pf.enf_FilterLen++] = htons (0x00FF);
  pf.enf_Filter[pf.enf_FilterLen++] = ENF_PUSHLIT | ENF_CAND;
  pf.enf_Filter[pf.enf_FilterLen++] = htons (IPPROTO_TCP);
  pf.enf_Filter[pf.enf_FilterLen++] = ENF_PUSHWORD + 6;
  pf.enf_Filter[pf.enf_FilterLen++] = ENF_PUSHLIT | ENF_EQ;
  pf.enf_Filter[pf.enf_FilterLen++] = htons (ETHERTYPE_IP);

  if (ioctl (iface, EIOCSETF, &pf) < 0) {
    perror ("ioctl (EIOCSETF)");
    exit (errno);
  }
  if (ioctl (iface, EIOCFLUSH, 0) < 0) {
    perror ("ioctl (EIOCFLUSH)");
    exit (errno);
  }
  fprintf (stderr, "Version %s listening on %s.\n\n", IS_VERSION, ifr.ifr_name);

  if (nolocal) {
    fprintf (stderr, "Warning: locally-originating packets not monitored!\n\n");
  }
}

/*
 * Needs a haircut.
 */
void
if_read (void)
{
  int buflen, pktlen, stamplen;
  struct enstamp *stamp;
  UCHAR aligned_buf[IF_BUFSIZ], rawbuf[IF_BUFSIZ];
  UCHAR *bufp;

  while ((buflen = read (iface, bufp = &rawbuf[0], IF_BUFSIZ)) >= 0) {
    /* Buffered. */
    while (buflen > 0) {
      stamp = (struct enstamp *)bufp;
      pktlen = stamp->ens_count;
      stamplen = stamp->ens_stamplen;
      memcpy ((char *)aligned_buf, (char *)bufp + linkhdr_len + stamplen,
	      (int)(pktlen - linkhdr_len));
      filter (aligned_buf);

      if (buflen == (pktlen + stamplen)) {
	break;
      }
      pktlen = ENALIGN (pktlen);
      buflen -= (pktlen + stamplen);
      bufp += (pktlen + stamplen);
    }
  }
}
