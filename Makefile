# Copyright (c) 1996 Jeffrey A. Uphoff
#
# ISSniff.  An Industrial-Strength Sniffer (eventually), primarily for Linux.
#
# $Id$

# *DEFINE THE OS*
OS	= linux
#OSNAME	= sunos		# Not done yet.

# Set level of DEBUG.
DEBUGS	= -DDEBUG

# General definitions.
DEFINES	= -D__USE_FIXED_PROTOTYPES__

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
SRCS	= $(OS).c sniff.c
OBJS	= $(SRCS:.c=.o)

all:	do-all

ifeq (.depend, $(wildcard .depend))
include .depend
do-all:	issniff
else
do-all: depend
	$(MAKE)
endif

dep depend:
	$(CPP) -M $(DEBUGS) $(DEFINES) $(SRCS) > .depend

$(PROG):	$(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS)

clean:
	$(RM) $(PROG) *.o core*

realclean distclean:	clean
	$(RM) .depend *~ \#*
