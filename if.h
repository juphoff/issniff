/* $Id$ */

int linkhdr_len;
struct ifreq ifr;

extern char *if_detect (int);

#define USE_TEMP_SOCK -1

#ifdef __linux__
# include <linux/if_ether.h>
#endif

#ifdef __sun__
# include <netinet/in_systm.h>
# include <netinet/in.h>
# include <netinet/if_ether.h>

extern int ioctl (int, int, caddr_t);
#endif
