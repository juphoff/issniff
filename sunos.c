/* $Id$ */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/nit_if.h>
#include <net/nit_pf.h>
#include <net/packetfilt.h>
#include "sunos.h"
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
  close (iface);
  fprintf (stderr, "Interface %s shut down; signal %d.\n", ifr.ifr_name, sig);
  exit (0);
}

/*
 * nit-picky!
 */
void
if_open (int nolocal)
{
  struct packetfilt pf;
  struct strioctl si;
  struct timeval to;
  u_int if_bufsiz = IF_BUFSIZ;
  u_long if_flags = NI_PROMISC;

  if (!*ifr.ifr_name) {
    char *interface = if_detect (USE_TEMP_SOCK);

    if (!interface) {
      fprintf (stderr, "Cannot auto-detect a default interface.  Odd, that.\n");
      exit (1);
    }
    assert (if_setname (interface) == 0);
  }
  if ((iface = open (NIT_DEV, O_RDONLY)) < 0) {
    perror ("open");
    exit (errno);
  }
  /* Read & discard. */
  if (ioctl (iface, I_SRDOPT, (char *)RMSGD) < 0) {
    perror ("ioctl (I_SRDOPT)");
    exit (errno);
  }
  /* Streams stack.  "pf" must precede "nbuf" for filtering to work right. */
  if (ioctl (iface, I_PUSH, "pf") < 0) {
    perror ("ioctl (I_PUSH)");
    exit (errno);
  }
  if (ioctl (iface, I_PUSH, "nbuf") < 0) {
    perror ("ioctl (I_PUSH)");
    exit (errno);
  }
  si.ic_timout = INFTIM;
  /* Set buffer flush timer. */
  si.ic_cmd = NIOCSTIME;
  to.tv_sec = IF_BUF_TIMER;
  to.tv_usec = 0;
  si.ic_len = sizeof (to);
  si.ic_dp = (char *)&to;

  if (ioctl (iface, I_STR, (char *)&si) < 0) {
    perror ("ioctl (I_STR: NIOCSTIME)");
    exit (errno);
  }
  /* Set nit buffer size.  Big means fewer read()'s, but more delay. */
  si.ic_cmd = NIOCSCHUNK;
  si.ic_len = sizeof (if_bufsiz);
  si.ic_dp = (char *)&if_bufsiz;

  if (ioctl (iface, I_STR, (char *)&si) < 0) {
    perror ("ioctl (I_STR: NIOCSCHUNK)");
    exit (errno);
  }
  /* Keep the high-level filtering in the kernel...we're not interested! */
  si.ic_cmd = NIOCSETF;
  pf.Pf_FilterLen = 0;
  /* Offsets are hard-coded here; they won't change in the life of IPV4. */
  pf.Pf_Filter[pf.Pf_FilterLen++] = ENF_PUSHWORD + 11;
  pf.Pf_Filter[pf.Pf_FilterLen++] = ENF_PUSHLIT | ENF_AND;
  pf.Pf_Filter[pf.Pf_FilterLen++] = htons (0x00FF);
  pf.Pf_Filter[pf.Pf_FilterLen++] = ENF_PUSHLIT | ENF_CAND;
  pf.Pf_Filter[pf.Pf_FilterLen++] = htons (IPPROTO_TCP);
  pf.Pf_Filter[pf.Pf_FilterLen++] = ENF_PUSHWORD + 6;
  pf.Pf_Filter[pf.Pf_FilterLen++] = ENF_PUSHLIT | ENF_EQ;
  pf.Pf_Filter[pf.Pf_FilterLen++] = htons (ETHERTYPE_IP);
  si.ic_len = sizeof (pf);
  si.ic_dp = (char *)&pf;
  
  if (ioctl (iface, I_STR, (char *)&si) < 0) {
    perror ("ioctl (I_STR: NIOCSETF)");
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
  /* Get promiscous. */
  si.ic_cmd = NIOCSFLAGS;
  si.ic_len = sizeof (if_flags);
  si.ic_dp = (char *)&if_flags;

  if (ioctl (iface, I_STR, (char *)&si) < 0) {
    perror ("ioctl (I_STR: NIOCSFLAGS)");
    exit (errno);
  }
  /* Flush the can before sitting down. */
  if (ioctl (iface, I_FLUSH, (char *)FLUSHR) < 0) {
    perror ("ioctl (I_FLUSH)");
    exit (errno);
  }
  fprintf (stderr, "Version %s listening on %s.\n\n", IS_VERSION, ifr.ifr_name);
  /* I want an option for local stuff, but I don't know how to do it yet! */
  fprintf (stderr, "Warning: locally-originating packets not monitored!\n\n");
}

/*
 * This could probably be tightened up a little.
 */
void
if_read (void)
{
  int bytes;
  struct nit_bufhdr *bufhdrp;
  UCHAR aligned_buf[IF_BUFSIZ], rawbuf[IF_BUFSIZ];
  UCHAR *bufp, *bufstop, *pktp;

  while ((bytes = read (iface, rawbuf, IF_BUFSIZ)) >= 0) {
    bufp = rawbuf;
    bufstop = rawbuf + bytes;

    /* Buffering makes this fun! */
    while (bufp < bufstop) {
      pktp = bufp;
      bufhdrp = (struct nit_bufhdr *)pktp;
      pktp += sizeof (*bufhdrp);
      bufp += bufhdrp->nhb_totlen;
      memcpy ((char *)aligned_buf, (char *)pktp + linkhdr_len, /* Align! */
	      (int)(bufhdrp->nhb_msglen - linkhdr_len));
      filter (aligned_buf);
    }
  }
}
