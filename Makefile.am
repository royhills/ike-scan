# Process this file with automake to produce Makefile.in
#
AM_CPPFLAGS = -DIKEDATADIR=\"$(pkgdatadir)\"
#
dist_pkgdata_DATA = ike-backoff-patterns ike-vendor-ids
bin_PROGRAMS = ike-scan
check_PROGRAMS = check-sizes check-hash
dist_check_SCRIPTS = check-run1 check-run2 check-run3
dist_man_MANS = ike-scan.1
ike_scan_SOURCES = ike-scan.c ike-scan.h error.c md5.c md5.h isakmp.c isakmp.h wrappers.c utils.c sha1.c
check_sizes_SOURCES = check-sizes.c error.c ike-scan.h
check_hash_SOURCES = check-hash.c error.c utils.c wrappers.c ike-scan.h md5.c md5.h sha1.c
ike_scan_LDADD = @COMPAT_OBJS@
ike_scan_DEPENDENCIES = @COMPAT_OBJS@
TESTS = $(check_PROGRAMS) $(dist_check_SCRIPTS)
EXTRA_ike_scan_SOURCES = getopt.c getopt.h getopt1.c inet_aton.c
EXTRA_DIST = udp-backoff-fingerprinting-paper.txt README-WIN32
