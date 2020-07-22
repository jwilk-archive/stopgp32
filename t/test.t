#!/bin/sh

# Copyright © 2018-2020 Jakub Wilk <jwilk@jwilk.net>
# SPDX-License-Identifier: MIT

set -e -u
echo 1..1
if printf zz | grep --color=yes --perl-regexp '(?<=z)z' > /dev/null 2>&1
then
    xgrep()
    {
        grep --color=yes --perl-regexp "(?<=\bkeyid [0-9A-F]{8})$1\$"
    }
else
    xgrep()
    {
        grep -w -E "keyid [0-9A-F]{8}$1"
    }
fi

here="${0%/*}"
here=$(readlink -f "$here")
prog="$here/../stopgp32"
tmpdir=$(mktemp -d -t stopgp32.XXXXXX)
cd "$tmpdir"
timeout 15s "$prog" -d "$here" 82B4B2CB
gpg --list-packets 82B4B2CB.pgp > 82B4B2CB.txt
xgrep 82B4B2CB < 82B4B2CB.txt
echo ok 1
cd /
rm -rf "$tmpdir"

# vim:ts=4 sts=4 sw=4 et ft=sh
