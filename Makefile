# Copyright © 2018 Jakub Wilk <jwilk@jwilk.net>
# SPDX-License-Identifier: MIT

CC ?= gcc -std=gnu99
CFLAGS ?= -g -O2
OPENMP_CFLAGS = -fopenmp
CFLAGS += -Wall -Wextra $(OPENMP_CFLAGS)
LDLIBS = -lcrypto

.PHONY: all
all: stopgp32

.PHONY: clean
clean:
	rm -f stopgp32

# vim:ts=4 sts=4 sw=4 noet
