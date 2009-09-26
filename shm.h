/* $Id$ */

/*
 * Interesting #define's:
 *
 * 		Linux		OSF/1
 * ------------------------------------------
 * SHMMAX:	16777216	4194304
 * SHMMIN:	1		1
 * SHMMNI:	128		100
 * SHMSEG:	128		32
 */

extern void shm_setup (void);
