/* $Id$ */

/*
 * General definitions
 */
#define CACHE_INC 16		/* Cache block increment. */
#define IS_MAXDATA 4096		/* Max data for connection: one page for fun. */
#define IS_TIMEOUT 3600		/* Max idle time for connection: one hour. */

/*
 * Function prototypes.
 */
extern char *get_interface (void);
extern void close_interface (int);
extern void filter (UCHAR *);
extern void ifread (void);
extern void open_interface (void);
extern void set_interface (const char *);

/*
 * Misc. macros.
 */
#define CHKOPT(FALLBACK) (atoi (optarg) ? atoi (optarg) : (FALLBACK))
#define YN(X) ((X) ? "yes" : "no")
