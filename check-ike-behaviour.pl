#!/usr/bin/perl -w
# $Id$
# check-ike-behaviour.pl -- Check IPsec host's behaviour to various IKE packets
#
# Author: Roy Hills
# Date: 23 June 2005
#
use strict;
#
if ($#ARGV != 1) {
   die "Usage: check-ike-behaviour.pl <host> <good_trans>\n";
}
#
my $host = shift;
my $good_trans = shift;
my $bad_trans = "8,5,7,2";
my $debug = 0;
#
my $result;

# Simple tests.  Key is test name, value is ike-scan option.
my %simple_tests = (
   non_zero_reserved_fields => '--mbz=255',
   invalid_major_version => '--headerver=0x30',
   invalid_minor_version => '--headerver=0x11',
   invalid_doi => '--doi=255',
   invalid_situation => '--situation=255',
   invalid_protocol => '--protocol=255',
   invalid_transform_id => '--transid=255',
   ephemeral_source_port => '--sport=0',
   header_length_too_small => '--headerlen=-1',
   header_length_too_large => '--headerlen=+1',
   header_length_too_large => '--headerlen=+1',
   non_zero_msgid => '--hdrmsgid=255',
   invalid_flags => '--hdrflags=255',
   invalid_cookie => '--cookie=0000000000000000'
);

# Range tests.  Key is test name, value is ike-scan option, lower & upper bounds
my %range_tests = (
   lifetime => '--lifetime:1:4000000000:28800',
   lifesize => '--lifetime:1:4000000000:1024',
   spi_size => '--spisize:1:1000:16'
);

# Check response to invalid transform
check_target_ok();
$result = run_ike_scan("--trans=$bad_trans $host");
print "invalid_transform\t$result\n";

# Perform simple tests
while (my($key, $value) = each(%simple_tests)) {
   check_target_ok();
   $result = run_ike_scan("--trans=$good_trans $value $host");
   $result = "no_response" if ($result =~ /^$/);
   print "$key\t$result\n";
}

# Perform range tests
while (my($key, $value) = each(%range_tests)) {
   if ($value =~ /^(.+):(.+):(.+):(.+)$/) {
      my $option = $1;
      my $min = $2;
      my $max = $3;
      my $good_value = $4;
      my $low;
      my $high;
      my $basic_response;

# Check good value.  If this works, then determine range, otherwise
# the option is not supported.
      $result=run_ike_scan("$option=$good_value --trans=$good_trans $host");
      $basic_response = get_basic_response($result);
      if ($basic_response =~ /Handshake returned/) {
         $low = binsearchlow("$good_value:$min:$max:$option");
         $high = binsearchhigh("$good_value:$min:$max:$option");
         print "$key\t$low:$high\n";
      } else {
         print "$key\tnot_supported\n";
      }
   } else {
      die "Incorrect format for range test $key: $value\n";
   }
}

# Run ike-scan with the given arguments, and return the output
# This assumes that only one target host is passed to ike-scan.
sub run_ike_scan {
   my $output = "";
   open(IKE, "ike-scan $_[0] |")  || die "Cannot run ike-scan\n";
   while (<IKE>) {
         chomp;
         if (/^[0-9.]+\t(.+)/) {
            $output = $1;
            last;
         }
      }
   close(IKE);
   return $output;
}

# Check that the target is OK.
# We define "OK" as meaning responds to ike-scan in any way
sub check_target_ok {
   my $known_good_check = "--trans=$good_trans $host";
   my $result;
   $result = run_ike_scan("$known_good_check");
   die "Target did not respond\n" unless $result;
}

# Determine basic ike-scan response
sub get_basic_response {
   my $basic_response = $_[0];
   $basic_response =~ s/\(.*//;
   $basic_response =~ s/ [A-Z]+=$//;
   $basic_response =~ s/ $//;
   return $basic_response;
}

# Search for low end of range
sub binsearchlow {
   my $lo;
   my $hi;
   my $val;
   my $result;
   my $min;
   my $max;
   my $option;
   my $basic_response;
   my $iter=1;

   ($val, $min, $max, $option) = split(/:/, $_[0]);
   $lo = $min;
   $hi = $val;
   while ($lo < $hi) {
      $val = int($lo + ($hi - $lo)/2);
      $result=run_ike_scan("$option=$val --trans=$good_trans $host");
      $basic_response = get_basic_response($result);
      print "$iter\t$lo\t$hi\t$val\t$basic_response\n" if $debug;
      if ($basic_response =~ /Handshake returned/) {
         $hi = $val;
      } else {
         $lo = $val + 1;
      }
      $iter++;
   }
   print "end\t$lo\t$hi\t$val\n" if $debug;
   return $hi;
}

# search for high end of range
sub binsearchhigh {
   my $lo;
   my $hi;
   my $val;
   my $result;
   my $min;
   my $max;
   my $option;
   my $basic_response;
   my $iter=1;

   ($val, $min, $max, $option) = split(/:/, $_[0]);
   $lo = $val;
   $hi = $max;
   while ($lo < $hi) {
      $val = int($lo + ($hi - $lo)/2);
      $result=run_ike_scan("$option=$val --trans=$good_trans $host");
      $basic_response = get_basic_response($result);
      print "$iter\t$lo\t$hi\t$val\t$basic_response\n" if $debug;
      if ($basic_response =~ /Handshake returned/) {
         $lo = $val + 1;
      } else {
         $hi = $val;
      }
      $iter++;
   }
   print "end\t$lo\t$hi\t$val\n" if $debug;
   if ($lo < $max) {
      return $lo-1;
   } else {
      return $lo;
   }
}
