# $Id$

include .version

# *DEFINE THE OS*
OS	= linux
#OSNAME	= sunos		# Not done yet.

# Set level of DEBUG.
DEBUGS	= -DDEBUG

# General definitions.
DEFINES	= -D__USE_FIXED_PROTOTYPES__ -DIS_VERSION=\"$(IS_VERSION)\"

# For normal use.
CC	= gcc
# Typical way to generate a.out binaries with an ELF-defaulting compiler.
#CC	= gcc -b i486-linuxaout

# The Ted Ts'o express.  :)~
WFLAGS	= -ansi -pedantic -Wall -Wwrite-strings -Wpointer-arith -Wcast-qual \
	  -Wcast-align -Wtraditional -Wstrict-prototypes -Wmissing-prototypes \
	  -Wnested-externs -Winline -Wshadow

# For normal use.
#CFLAGS	= -O6 -pipe -fomit-frame-pointer $(DEBUGS) $(DEFINES) $(WFLAGS)
#LDFLAGS	= -s
# For development/debugging.
CFLAGS	= -g -O6 -pipe -fomit-frame-pointer $(DEBUGS) $(DEFINES) $(WFLAGS)
LDFLAGS	= -g

.PHONY:	all clean distclean realclean

PROG	= issniff
MANEXT	= 8
SRCS	= $(OS).c sniff.c
MANSRC	= $(PROG).man
OBJS	= $(SRCS:.c=.o)
MANUAL	= $(MANSRC:.man=.$(MANEXT))

all:	do-all

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
	$(RM) $(PROG) $(MANUAL) *.o core*

realclean distclean:	clean
	$(RM) .depend *~ \#*
