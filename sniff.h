/* $Id$ */

/* General definitions. */
#define CACHE_INC 16		/* Cache block increment size. */
#define CACHE_SLACK (cache_increment >> 1) /* Management slack. */
#define IS_BUFSIZ 2048		/* Bigger than necessary. */
#define IS_MAXDATA 8192		/* Overrideable on the command line. */
#define IS_TIMEOUT 3600		/* Seconds idle to timeout a node. */

/* Function prototypes. */
extern char *get_interface (void);
extern void close_interface (int);
extern void open_interface (void);
extern void set_interface (const char *);

/* Global variables. */
int iface;
