
curdir := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
CPPFLAGS += -O2 -DSASR -DNeedFunctionPrototypes=1 -I$(curdir)/inc

SRCS := $(wildcard src/*.c)
OBJS := ${SRCS:.c=.o}

# targets
libgsm.a: $(OBJS)
	@echo "AR $@"
	@$(AR) crus $@ $^

clean:
	@$(RM) -f $(OBJS) libgsm.a

.PHONY: clean

