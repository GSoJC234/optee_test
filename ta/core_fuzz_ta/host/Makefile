# SPDX-License-Identifier: BSD-2-Clause
ROOT ?= $(abspath $(CURDIR)/../../../..)
SYSROOT := $(ROOT)/out-br/host/aarch64-buildroot-linux-gnu/sysroot
CC := $(ROOT)/out-br/host/bin/aarch64-linux-gnu-gcc

CPPFLAGS += -I../include -I$(ROOT)/optee_os/lib/libutee/include -I$(SYSROOT)/usr/include
CFLAGS += -O2 -Wall -Wextra -Werror
LDLIBS += -L$(SYSROOT)/usr/lib -lteec

.PHONY: all clean
all: core_fuzz_ta_ca core_fuzz_ta_fuzzer

core_fuzz_ta_ca: core_fuzz_ta_ca.c ../include/core_fuzz_ta.h $(ROOT)/optee_os/lib/libutee/include/pta_core_fuzz_cov.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDLIBS)

core_fuzz_ta_fuzzer: core_fuzz_ta_fuzzer.c ../include/core_fuzz_ta.h $(ROOT)/optee_os/lib/libutee/include/pta_core_fuzz_cov.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f core_fuzz_ta_ca core_fuzz_ta_fuzzer
