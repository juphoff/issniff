/* sunos.c,v 2.8 1996/08/15 22:51:10 juphoff Exp */

/* THIS CODE IS CURRENTLY A *REAL* MESS! */

/*
 * I gotta' thank the 'tcpdump' authors for their indirect help for
 * Solaris; looking at pcap-dlpi.c proved very useful while coding this.
 */

#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>
#include <sys/dlpi.h>
#include <sys/pfmod.h>
#include "sol.h"
#include "sniff.h"
#include "if.h"

/*
 * Local variables.
 */
static int iface;

/*
 * Local function definitions.
 */
static void do_putmsg (char *, size_t, const char *);
static void _str_ioctl (int, char *, size_t, const char *);

#define str_ioctl(CMD, PTR, SIZ) _str_ioctl(CMD, PTR, SIZ, #CMD)

/*
 * Utility functions.
 */
static void
_str_ioctl (int cmd, char *ptr, size_t len, const char *errmsg)
{
  struct strioctl str;

  str.ic_cmd = cmd;
  str.ic_timout = INFTIM;
  str.ic_dp = ptr;
  str.ic_len = len;

  if (ioctl (iface, I_STR, &str) < 0) {
    perror (errmsg);
    exit (errno);
  }
}

static void
do_putmsg (char *req, size_t sreq, const char *errmsg)
{
  int flags = 0;
  struct strbuf ctl;

  ctl.maxlen = 0;
  ctl.len = sreq;
  ctl.buf = req;

  if (putmsg (iface, &ctl, (struct strbuf *)NULL, flags) < 0) {
    perror (errmsg);
    exit (errno);
  }
}

/*
 * Signal handler.
 */
void
if_close_net (int sig)
{
  close (iface);
  fprintf (stderr, "Interface %s shut down; signal %d.\n", ifr.ifr_name, sig);

  if (sig) {
    exit (0);
  }
}

/*
 * dlpi.
 */
void
if_open_net (int nolocal)
{
  char dev_name[100];		/* Need better length definition. */

  if (!*ifr.ifr_name) {
    char *interface = if_detect (USE_TEMP_SOCK);

    if (!interface) {
      fprintf (stderr, "Cannot auto-detect a default interface.  Odd, that.\n");
      exit (1);
    }
    assert (if_setname (interface) == SUCCESSFUL);
  }
  sprintf (dev_name, "/dev/%s", ifr.ifr_name);
  dev_name[strlen (dev_name) - 1] = '\0';

  /* Open device. */
  if ((iface = open (dev_name, O_RDWR)) < 0) {
    perror ("open");
    exit (errno);
  }
  /* Attach device to stream. */
  {
    dl_attach_req_t req;

    req.dl_primitive = DL_ATTACH_REQ;
    req.dl_ppa =
      (unsigned long int)ifr.ifr_name[strlen(ifr.ifr_name) - 1] - '0';
    do_putmsg ((char *)&req, sizeof (dl_attach_req_t), "DL_ATTACH_REQ");
  }
  /* Turn on promiscuous mode. */
  {
    dl_promiscon_req_t req;

    req.dl_primitive = DL_PROMISCON_REQ;
    req.dl_level = DL_PROMISC_PHYS;
    do_putmsg ((char *)&req, sizeof (dl_promiscon_req_t), "DL_PROMISC_PHYS");

    req.dl_primitive = DL_PROMISCON_REQ;
    req.dl_level = DL_PROMISC_SAP;
    do_putmsg ((char *)&req, sizeof (dl_promiscon_req_t), "DL_PROMISC_SAP");
#if 0
    req.dl_primitive = DL_PROMISCON_REQ;
    req.dl_level = DL_PROMISC_MULTI;
    do_putmsg ((char *)&req, sizeof (dl_promiscon_req_t), "DL_PROMISC_MULTI");
#endif
  }
  /* To get the ethernet header. */
  str_ioctl (DLIOCRAW, NULL, 0);

  /* Streams stack: "pfmod" before "bufmod" for filtering to work right. */
#if 1
  if (ioctl (iface, I_PUSH, "pfmod") < 0) {
    perror ("ioctl (I_PUSH)");
    exit (errno);
  }
#endif
  /* To buffer the data. */
  if (ioctl (iface, I_PUSH, "bufmod") < 0) {
    perror ("ioctl (I_PUSH)");
    exit (errno);
  }
  /* Set buffering parameters. */
  {
#if 1				/* Bufmod appears to be broken in 2.4. */
    unsigned long int if_bufsiz = 0;
#else
    unsigned long int if_bufsiz = IF_BUFSIZ;
#endif

    str_ioctl (SBIOCSCHUNK, (char *)&if_bufsiz, sizeof (unsigned long int));
  }
  /* Set up the bufmod flags */
  {
    unsigned long int flag = 0;

    str_ioctl (SBIOCGFLAGS, (char *)&flag, sizeof (unsigned long int));
    flag |= SB_NO_DROPS;
    str_ioctl (SBIOCSFLAGS, (char *)&flag, sizeof (unsigned long int));
  }
  /* Set up the bufmod timeout. */
  {
    struct timeval to;

    to.tv_sec = IF_BUF_TIMER;
    to.tv_usec = 0;
    str_ioctl (SBIOCSTIME, (char *)&to, sizeof (struct timeval));
  }
  /* Flush the can. */
  if (ioctl (iface, I_FLUSH, FLUSHR) < 0) {
    perror ("ioctl (I_FLUSH)");
    exit (errno);
  }

#if 1
  {
    struct packetfilt pf;

    /* Keep the high-level filtering in the kernel...we're not interested! */
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
    str_ioctl (PFIOCSETF, (char *)&pf, sizeof (struct packetfilt));
  }
#endif
  fprintf (stderr, "Version %s listening on %s.\n\n", IS_VERSION, ifr.ifr_name);
  /* /dev/nit just can't do locally-originated stuff.  Blah. */
/*   fprintf (stderr, "Warning: locally-originated packets not monitored!\n\n"); */
}

/*
 * This could probably be tightened up a little.
 */
void
if_read_ip_net (void (*filter) (UCHAR *, int))
{
  int bytes;
  struct sb_hdr *bhdrp;
  UCHAR aligned_buf[IF_BUFSIZ], rawbuf[IF_BUFSIZ];
  UCHAR *bufp, *bufstop, *pktp;

  while ((bytes = read (iface, rawbuf, IF_BUFSIZ)) > 0) {
    bufp = rawbuf;
    bufstop = &rawbuf[bytes];

    /* Buffering makes this fun! */
    while (bufp < bufstop) {
      bhdrp = (struct sb_hdr *)bufp;
      pktp = bufp + sizeof (*bhdrp);
      bufp += bhdrp->sbh_totlen;
      memcpy ((char *)aligned_buf, (char *)&pktp[linkhdr_len], /* Align! */
	      (unsigned int)(bhdrp->sbh_msglen - linkhdr_len));
      filter (aligned_buf, bhdrp->sbh_msglen - linkhdr_len - 2); /* Fix me! */
    }
  }
}
