/* $Id$ */

/*
 * Interesting #define's:
 *
 * 		Linux		SunOS		OSF/1
 * ----------------------------------------------------------
 * SHMMAX:	16777216	1048576		4194304
 * SHMMIN:	1		1		1
 * SHMMNI:	128		100		100
 * SHMSEG:	128		?		32
 */

void shm_setup (void);
