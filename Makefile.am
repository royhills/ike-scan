# $Id$
# Process this file with automake to produce Makefile.in
#
AM_CPPFLAGS = -DIKEDATADIR=\"$(pkgdatadir)\"
#
dist_pkgdata_DATA = ike-backoff-patterns ike-vendor-ids psk-crack-dictionary
bin_PROGRAMS = ike-scan psk-crack
check_PROGRAMS = check-sizes check-hash
dist_check_SCRIPTS = check-run1 check-run2 check-run3 check-psk-crack-1 check-psk-crack-2 check-psk-crack-3 check-psk-crack-4 check-packet check-decode check-error
dist_man_MANS = ike-scan.1 psk-crack.1
ike_scan_SOURCES = ike-scan.c ike-scan.h error.c isakmp.c isakmp.h wrappers.c utils.c mt19937ar.c hash_functions.h
ike_scan_LDADD = $(LIBOBJS)
psk_crack_SOURCES = psk-crack.c psk-crack.h error.c wrappers.c utils.c mt19937ar.c hash_functions.h
psk_crack_LDADD = $(LIBOBJS)
check_sizes_SOURCES = check-sizes.c error.c ike-scan.h
check_sizes_LDADD = $(LIBOBJS)
check_hash_SOURCES = check-hash.c error.c utils.c wrappers.c ike-scan.h mt19937ar.c hash_functions.h
check_hash_LDADD = $(LIBOBJS)
TESTS = $(check_PROGRAMS) $(dist_check_SCRIPTS)
EXTRA_DIST = udp-backoff-fingerprinting-paper.txt README-WIN32 make-win32-zipfile.sh pkt-default-proposal.dat pkt-custom-proposal.dat pkt-aggressive.dat pkt-malformed.dat pkt-ikev2.dat pkt-main-mode-response.dat pkt-aggr-mode-response.dat pkt-notify-response.dat pkt-v2-sainit-response.dat pkt-v2-notify-response.dat pkt-aggr-cert-response.dat pkt-main-natt-response.dat pkt-checkpoint-notify.dat pkt-single-trans.dat
