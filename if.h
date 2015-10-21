extern int linkhdr_len;

extern char *if_detect (int);

#define USE_TEMP_SOCK -1

#ifdef __linux__
# include <net/if.h>
# include <linux/if_ether.h>
#endif /* __linux__ */

extern struct ifreq ifr;
