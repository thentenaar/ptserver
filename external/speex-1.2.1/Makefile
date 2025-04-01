
curdir := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
CPPFLAGS += -O3 -I$(curdir)/include -I$(curdir)/include/speex
CPPFLAGS += -I$(curdir)/libspeex -DEXPORT=""

# Floating-point by default
FIXED_POINT ?=
ifneq ($(FIXED_POINT),)
CPPFLAGS += -DFIXED_POINT -DDISABLE_FLOAT_API
FFTSRC := libspeex/kiss_fft.c libspeex/kiss_fftr.c
else
CPPFLAGS += -DFLOATING_POINT
FFTSRC := libspeex/smallft.c
endif

SRCS := $(FFTSRC)               \
	libspeex/cb_search.c        \
	libspeex/exc_10_32_table.c  \
	libspeex/exc_8_128_table.c  \
	libspeex/filters.c          \
	libspeex/gain_table.c       \
	libspeex/hexc_table.c       \
	libspeex/high_lsp_tables.c  \
	libspeex/lsp.c              \
	libspeex/ltp.c              \
	libspeex/speex.c            \
	libspeex/stereo.c           \
	libspeex/vbr.c              \
	libspeex/vq.c               \
	libspeex/bits.c             \
	libspeex/exc_10_16_table.c  \
	libspeex/exc_20_32_table.c  \
	libspeex/exc_5_64_table.c   \
	libspeex/exc_5_256_table.c  \
	libspeex/gain_table_lbr.c   \
	libspeex/hexc_10_32_table.c \
	libspeex/lpc.c              \
	libspeex/lsp_tables_nb.c    \
	libspeex/modes.c            \
	libspeex/modes_wb.c         \
	libspeex/nb_celp.c          \
	libspeex/quant_lsp.c        \
	libspeex/sb_celp.c          \
	libspeex/speex_callbacks.c  \
	libspeex/speex_header.c     \
	libspeex/window.c           \
	libspeex/resample.c

OBJS := ${SRCS:.c=.o}

# targets
libspeex.a: $(OBJS)
	@echo "AR $@"
	@$(AR) crus $@ $^

clean:
	@$(RM) -f $(OBJS) libspeex.a

.PHONY: clean

