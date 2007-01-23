#!/bin/sh
# $Id$
#
# make-win32-zipfile.sh -- Create Win32 distribution zip file
#
# This shell script creates the ike-scan Win32 binary zip file
# ike-scan-win32-<ver>.zip. It is used it to create the ike-scan windows binary
# package for each new version.  Most users won't need to use this script, and
# it can be omitted from binary packages without any loss of functionallity.
#
# It must be run under Cygwin after ike-scan has been configured, built and
# tested. It will not work on Unix or Linux systems.
#
# The resulting zipfile can be used on any Win32 system.
#
FILES="udp-backoff-fingerprinting-paper.txt AUTHORS ChangeLog COPYING ike-backoff-patterns ike-scan.exe ike-vendor-ids NEWS psk-crack.exe psk-crack-dictionary README README-WIN32 TODO /cygdrive/c/cygwin/bin/cygwin1.dll"

ZIPFILE="ike-scan-win32-1.9.zip"
OPTS="-j -9"
#
zip $OPTS $ZIPFILE $FILES
