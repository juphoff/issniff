/* $Id$ */

/* General definitions. */
#define IS_BUFSIZ 2048		/* Bigger than necessary. */
#define IS_MAXDATA 8192		/* Overrideable on the command line. */

/* Function prototypes. */
extern void open_interface (void);
extern void close_interface (int);

/* Global variables. */
int iface;
