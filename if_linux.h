/* $Id$ */

/*
 * Interface type prefixes and their link-level packet header sizes.
 */
static struct {
  const char *type;
  int hdr_len;
} if_types[] = {
  { "eth", sizeof (struct ethhdr) },
  { "sl", 0 },
  { "lo", sizeof (struct ethhdr) },
  { "dummy", sizeof (struct ethhdr) },
  /* Still need PPP. */
  { NULL }
};
