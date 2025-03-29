#
# ptserver: A server for the Paltalk protocol
# Copyright (C) 2004 - 2025 Tim Hentenaar.
#
# This code is licensed under the Simplified BSD License.
# See the LICENSE file for details.

LIBS=-lsqlite3 -lm
CPPFLAGS=-O2 -D_XOPEN_SOURCE=500 -DNDEBUG -Wall -Wextra -Wno-implicit-fallthrough -Wno-overlength-strings
LDFLAGS=
EXLIBS=external/gsm-1.0.12/libgsm.a

# Gather the sources
SRCS  := $(wildcard src/*.c)
HS    := $(wildcard src/*.h)
OBJS  := ${SRCS:.c=.o}
STRIP := $(shell which strip)

#
# Targets
#

all: ptserver

ptserver: $(HS) $(OBJS) $(EXLIBS)
	@echo "  LD $@"
	@$(CC) -o $@ $(OBJS) $(LDFLAGS) $(LIBS) $(EXLIBS)
ifneq ($(STRIP),)
	@$(STRIP) -S -R .gnu.hash -R .note -R .comment $@
endif

external/gsm-1.0.12/libgsm.a:
	@$(MAKE) -C external/gsm-1.0.12 libgsm.a

clean:
	@$(RM) -f $(OBJS) ptserver
	@$(MAKE) -C external/gsm-1.0.12 clean

.PHONY: clean
