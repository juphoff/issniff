# $Id$
#
# THIS MAKEFILE *REQUIRES* GNU MAKE!
# ----------------------------------

include .version

# Only works for Linux right now--make generic!
OS	:= $(shell uname | tr '[A-Z]' '[a-z]')

# *DEFINE THE OS* (if not Linux)
#OS	= osf		# Works.
#OS	= sunos		# Works.
#OS	= sol		# Pre-alpha: still SEGV's mysteriously.

# Set level of DEBUG.
DEBUGS	= -DDEBUG

# OS-specific defines.
DEFINES_linux	= -D_POSIX_SOURCE -DSUPPORT_TCPDUMP
DEFINES_sunos	= -D__USE_FIXED_PROTOTYPES__
DEFINES_sol	= -D__EXTENSIONS__

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

# OS-specific C compiler flags.
CFLAGS_linux	= -fomit-frame-pointer -fno-strength-reduce

# For normal use.
#CFLAGS	= -O6 $(CFLAGS_$(OS)) $(DEBUGS) $(DEFINES) $(WFLAGS)
#LDFLAGS	= -s

# For development/debugging.
CFLAGS	= -g -O6 $(CFLAGS_$(OS)) $(DEBUGS) $(DEFINES) $(WFLAGS)
LDFLAGS	= -g

# OS-specific feature support.
SRCS_linux	= pcap-tcpdump.c

# OS-specific libraries.
LIBS_sol	= -lsocket -lnsl

PROG	= issniff
MANEXT	= 8
SRCS	= $(OS).c filter.c if.c shm.c sniff.c $(SRCS_$(OS))
MANSRC	= $(PROG).man
OBJS	= $(SRCS:.c=.o)
LIBS	= $(LIBS_$(OS))
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
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(MANUAL):	$(MANSRC) .version
	$(RM) $@
	sed 's/@@IS_VERSION@@/$(IS_VERSION)/' $< > $@

clean:
	$(RM) $(PROG) *.o core*

realclean distclean:	clean
	$(RM) $(MANUAL) .depend *~ \#*
