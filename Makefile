# $Id$
#
# THIS MAKEFILE *REQUIRES* GNU MAKE!
# ----------------------------------

include .version

# *DEFINE THE OS*
OS	= linux
#OS	= osf		# Works.
#OS	= sunos		# Works.

# Set level of DEBUG.
DEBUGS	= -DDEBUG

# Optional OS-specific defines.
DEFINES_linux	= -D_POSIX_SOURCE
DEFINES_sunos	= -D__USE_FIXED_PROTOTYPES__

# General definitions.
DEFINES	= $(DEFINES_$(OS)) -DIS_VERSION=\"$(IS_VERSION)\" -DOSVER=\"$(OS)\"

# THIS CODE HAS NOT BEEN TESTED UNDER ANY COMPILER OTHER THAN GCC!
#
# For normal use.
CC	= gcc
# Typical Linux way to generate a.out binaries with an ELF-defaulting compiler.
#CC	= gcc -b i486-linuxaout

# The Ted Ts'o express.  Noisy under e.g. SunOS.
WFLAGS	= -ansi -pedantic -Wall -Wcast-align -Wcast-qual -Winline \
	  -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wshadow \
	  -Wstrict-prototypes -Wwrite-strings 

# Optional OS-specific flags.
CFLAGS_linux	= -fomit-frame-pointer -fno-strength-reduce

# For normal use.
#CFLAGS	= -O6 $(CFLAGS_$(OS)) $(DEBUGS) $(DEFINES) $(WFLAGS)
#LDFLAGS	= -s

# For development/debugging.
CFLAGS	= -g -O6 $(CFLAGS_$(OS)) $(DEBUGS) $(DEFINES) $(WFLAGS)
LDFLAGS	= -g

.PHONY:	all clean distclean realclean

PROG	= issniff
MANEXT	= 8
SRCS	= $(OS).c filter.c if.c shm.c sniff.c
MANSRC	= $(PROG).man
OBJS	= $(SRCS:.c=.o)
MANUAL	= $(MANSRC:.man=.$(MANEXT))

all:	do-all

world:	distclean
	$(MAKE)

ifeq (.depend, $(wildcard .depend))
include .depend
do-all:	$(PROG) $(MANUAL)
else
do-all: depend
	$(MAKE)
endif

dep depend:
	$(CPP) -M $(DEBUGS) $(DEFINES) $(SRCS) > .depend

$(PROG):	$(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

$(MANUAL):	$(MANSRC) .version
	$(RM) $@
	sed 's/@@IS_VERSION@@/$(IS_VERSION)/' $< > $@

clean:
	$(RM) $(PROG) *.o core*

realclean distclean:	clean
	$(RM) $(MANUAL) .depend *~ \#*
