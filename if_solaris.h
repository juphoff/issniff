/* $Id$ */

/*
 *  Interface type prefixes and their link-level packet header sizes.
 */
static struct {
  const char *type;
  int hdr_len;
} if_types[] = {
  { "le", sizeof (struct ether_header) },
  { NULL }			/* Any others for Solaris?  Not anytime soon! */
};

extern int socket (int, int, int);
