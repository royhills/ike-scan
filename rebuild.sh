#!/bin/sh
# $Id$
# rebuild.sh -- simple shell script to rebuild autoconf and automake
#
echo "aclocal"
aclocal
echo "automake"
automake
echo "autoconf"
autoconf
echo "autoheader"
autoheader
