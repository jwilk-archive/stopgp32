# Copyright © 2018 Jakub Wilk <jwilk@jwilk.net>
# SPDX-License-Identifier: MIT

ifeq "$(origin CC)" "default"
CC = gcc -std=gnu99
endif
CFLAGS ?= -g -O2
OPENMP_CFLAGS = -fopenmp
CFLAGS += -Wall -Wextra $(OPENMP_CFLAGS)
LDLIBS = -lcrypto

.PHONY: all
all: stopgp32

.PHONY: test
test: all
	test/run

.PHONY: clean
clean:
	rm -f stopgp32

.error = GNU make is required

# vim:ts=4 sts=4 sw=4 noet
