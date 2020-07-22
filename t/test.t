#!/bin/sh

# Copyright © 2018-2020 Jakub Wilk <jwilk@jwilk.net>
# SPDX-License-Identifier: MIT

set -e -u
echo 1..1
if printf zz | grep --color --perl-regexp '(?<=z)z' > /dev/null 2>&1
then
    xgrep()
    {
        grep --color --perl-regexp "(?<=\bkeyid [0-9A-F]{8})$1\$"
    }
else
    xgrep()
    {
        grep -w -E "keyid [0-9A-F]{8}$1"
    }
fi

here="${0%/*}"
cd "$here"
p=""
rm -f 82B4B2CB.pgp 82B4B2CB.txt
timeout 15s ../stopgp32 -d . 82B4B2CB
gpg --list-packets 82B4B2CB.pgp > 82B4B2CB.txt
xgrep 82B4B2CB < 82B4B2CB.txt
rm -f 82B4B2CB.pgp 82B4B2CB.txt
echo ok 1

# vim:ts=4 sts=4 sw=4 et ft=sh
