#!/usr/bin/perl
use strict;
use Mail::SPF::Iterator;
#$Mail::SPF::Iterator::DEBUG = 1;

my ($ip,$sender,$helo,$local) = @ARGV;
($ip && $sender) or die <<USAGE;

Usage: $0 Ip Sender Helo [Localname]
lookup SPF result, returns SPF-Received header
Example: 
$0 10.0.3.4 user\@example.com smtp.example.com smtp.example.local

USAGE

my $spf = Mail::SPF::Iterator->new( $ip,$sender,$helo || '',$local );
my @rv = $spf->lookup_blocking;
print $spf->mailheader( @rv ),"\n";

