#!/bin/sh
# $Id$
# rebuild.sh -- simple shell script to rebuild autoconf and automake
#
echo "aclocal"
aclocal
echo "autoheader"
autoheader
echo "automake --add-missing"
automake --add-missing
echo "autoconf"
autoconf
