# Process this file with automake to produce Makefile.in
#
CPPFLAGS = -DIKEDATADIR=\"$(pkgdatadir)\" @CPPFLAGS@
pkgdata_DATA = ike-backoff-patterns
bin_PROGRAMS = ike-scan
man_MANS = ike-scan.1
ike_scan_SOURCES = ike-scan.c ike-scan.h error.c md5.c md5.h isakmp.h
ike_scan_LDADD = @COMPAT_OBJS@
ike_scan_DEPENDENCIES = @COMPAT_OBJS@
EXTRA_ike_scan_SOURCES = getopt.c getopt.h getopt1.c
# I should be able to avoid having data_DATA and man_MANS here by using the
# dist_ prefix e.g. dist_man_MANS.  However, this doesn't work with
# automake 1.4 and autoconf 2.53.
EXTRA_DIST = $(pkgdata_DATA) $(man_MANS) udp-backoff-fingerprinting-paper.txt README-WIN32
