/* $Id$ */

/*
 *  Interface type prefixes and their link-level packet header sizes.
 */
static struct {
  const char *type;
  int hdr_len;
} if_types[] = {
  { "tu", sizeof (struct ether_header) },
  { NULL }			/* Any others for SunOS?  Not anytime soon! */
};
