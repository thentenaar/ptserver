#
# ptserver: A server for the Paltalk protocol
# Copyright (C) 2004 - 2024 Tim Hentenaar.
#
# This code is licensed under the Simplified BSD License.
# See the LICENSE file for details.
LIBS=-lsqlite3 -lm

# Gather the sources
SRCS := $(wildcard src/*.c)
HS := $(wildcard src/*.h)

# .c to .o
OBJS = ${SRCS:.c=.o}

#
# Targets
#

all: ptserver

ptserver: $(OBJS)
	@echo "  LD $@"
	@$(CC) -o $@ $^ $(LDFLAGS) $(LIBS)

clean:
	@$(RM) -f $(OBJS) ptserver

.PHONY: clean
