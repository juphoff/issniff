/* $Id$ */

/*
 * General definitions
 */
/*  "Hard" definitions. */
#define IS_BUFSIZ 2048		/* Bigger than necessary. */

/*  "Soft" (overrideable on the command line) definitions. */
#define CACHE_INC 16		/* Cache block increment. */
#define IS_MAXDATA 4096		/* Max data for connection: one page for fun. */
#define IS_TIMEOUT 3600		/* Max idle time for connection: one hour. */

/*
 * Function prototypes.
 */
extern char *get_interface (void);
extern void close_interface (int);
extern void open_interface (void);
extern void set_interface (const char *);

/*
 * Global variables.
 */
int iface;

/*
 * Misc. macros.
 */
#define CACHE_SLACK (cache_increment >> 1) /* Management slack. */
#define YN(X) ((X) ? "yes" : "no")
