/* $Id$ */

#include <stdlib.h>
#include "memory.h"

/*
 * Error-checking malloc() wrapper.
 */
void *
xmalloc (size_t size)
{
  void *ptr;

  if (size == 0)
    return (void *)NULL;

  if (!(ptr = malloc (size))) {
    perror ("malloc");
    exit (errno);
  }
  return ptr;
}

/*
 * Need a realloc() wrapper here.  I'll have to snitch one from my DBD code.
 */
