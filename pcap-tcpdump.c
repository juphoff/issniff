/* $Id$ */

/*
 * Only supported under Linux at this point!
 */

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/if.h>
#include OSVER".h"
#include "sniff.h"
#include "if.h"
#include "pcap-tcpdump.h"

/*
 * Local variables.
 */
static int byteswapped = 0;
static int iface;

/*
 * Misc. local macros.
 */
#define FIXSHORT(X) (byteswapped ? ntohs (X) : (X))
#define FIXLONG(X) (byteswapped ? ntohl (X) : (X))

/*
 * Invisible global shit.
 */
extern char if_name[];

/*
 * Signal handler.
 */
void
if_close_pcap (int sig)
{
  close (iface);
  fprintf (stderr, "\nClosed input file \"%s\"\n", if_name);

  if (sig) {
    exit (0);
  }
}

/*
 * For reading from a 'tcpdump -w' file.
 */
void
if_open_pcap (int nolocal)	/* "nolocal" is meaningless here. */
{
  struct pcap_file_header hdr;

  if ((iface = open (if_name, O_RDONLY)) < 0) {
    perror ("open");
    exit (errno);
  }
  if ((read (iface, &hdr, sizeof (struct pcap_file_header))) !=
      sizeof (struct pcap_file_header)) {
    int err = errno;

    perror ("read (pcap_file_header)");
    if_close_pcap (0);
    exit (err);
  }
  if (hdr.magic != TCPDUMP_MAGIC) {
    if (ntohl (hdr.magic) != TCPDUMP_MAGIC) {
      fputs ("Unknown/bad dump file format.\n", stderr);
      if_close_pcap (0);
      exit (-1);
    }
    fputs ("Note: dump file is byteswapped.\n", stderr);
    byteswapped = 1;
  }
  if ((FIXSHORT (hdr.version_major) != PCAP_VERSION_MAJOR) ||
      (FIXSHORT (hdr.version_minor) != PCAP_VERSION_MINOR)) {
    fprintf (stderr, "Wrong dump file version format: %d.%d\n",
	     FIXSHORT (hdr.version_major), FIXSHORT (hdr.version_minor));
    fprintf (stderr, "(Only version %d.%d is currently supported.)\n",
	     PCAP_VERSION_MAJOR, PCAP_VERSION_MINOR);
    if_close_pcap (0);
    exit (-1);
  }
  /* Should make IF_BUFSIZ dynamic.... */
  if (FIXLONG (hdr.snaplen) > IF_BUFSIZ) {
    fprintf (stderr, "File snapshot length %ld too long for IF_BUFSIZ of %d.\n",
	     FIXLONG (hdr.snaplen), IF_BUFSIZ);
    if_close_pcap (0);
    exit (-1);
  }
  fprintf (stderr, "Version %s reading from file \"%s\"\n\n", IS_VERSION,
	   if_name);
}

/*
 * Read from a 'tcpdump -w' file.  Still needs some work.
 */
void
if_read_ip_pcap (void (*filter) (UCHAR *, int))
{
  int bytes;
  UCHAR buf[IF_BUFSIZ];
  struct pcap_pkthdr hdr;

  /* Move me! */
  linkhdr_len = 14;

  for (;;) {
    if ((bytes = read (iface, &hdr, sizeof (struct pcap_pkthdr))) !=
	sizeof (struct pcap_pkthdr)) {
      if (bytes == 0) {
	fprintf (stderr, "\n** End of file...dumping what's left.\n\n");
	raise (SIGINT);		/* FIX ME! */
      }
      perror ("read (pcap_pkthdr)");
      return;
    }
    if ((bytes = read (iface, &buf, FIXLONG (hdr.caplen))) !=
	FIXLONG (hdr.caplen)) {
      perror ("read (packet)");
      return;
    }
    if (ETHTYPE ((ETHhdr *)buf) == IPTYPE) {
      filter (&buf[linkhdr_len], bytes - linkhdr_len);
    }
  }
}
