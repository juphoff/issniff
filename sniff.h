/* $Id$ */

/*
 * General definitions
 */
#define CACHE_INC 16		/* Cache block increment, arbitrary. */
#define IS_MAXDATA 4096		/* Max data for connection, arbitrary. */
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
extern void if_close_net (int);
extern void if_open_net (int);
extern void if_read_ip (void (*) (UCHAR *, int));
#if 0
extern void if_read_ip_raw (void (*) (UCHAR *, int));
#endif
