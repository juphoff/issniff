/* $Id$ */

/*
 * General definitions
 */
#define CACHE_INC 16		/* Cache block increment. */
#define IS_MAXDATA 4096		/* Max data for connection: one page for fun. */
#define IS_TIMEOUT 3600		/* Max idle time for connection: one hour. */

/*
 * Colors.  Feel free to diddle....
 */
#define FROM_COLOR 36		/* Cyan. */
#define TO_COLOR 33		/* Yellow. */
#define NO_COLOR 0

/*
 * Function prototypes.
 */
extern char *if_getname (void);
extern int if_setname (const char *);
extern void filter (UCHAR *);
extern void if_close (int);
extern void if_open (int);
extern void if_read (void);

/*
 * Misc. macros.
 */
#define CHKOPT(FALLBACK) (atoi (optarg) ? atoi (optarg) : (FALLBACK))
#define YN(X) ((X) ? "yes" : "no")
