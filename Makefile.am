# Process this file with automake to produce Makefile.in
#
CPPFLAGS = -DDATADIR=\"$(datadir)\" @CPPFLAGS@
data_DATA = ike-backoff-patterns
bin_PROGRAMS = ike-scan
ike_scan_SOURCES = ike-scan.c ike-scan.h error.c md5.c md5.h isakmp.h
ike_scan_LDADD = @COMPAT_OBJS@
ike_scan_DEPENDENCIES = @COMPAT_OBJS@
EXTRA_ike_scan_SOURCES = getopt.c getopt.h getopt1.c
EXTRA_DIST = $(data_DATA) udp-backoff-fingerprinting-paper.txt
