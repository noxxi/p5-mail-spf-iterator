#!/usr/bin/perl
use strict;
use warnings;
use Mail::SPF::Iterator;
use Getopt::Long qw(:config posix_default bundling);

#### Options
GetOptions(
	'd|debug' => \$Mail::SPF::Iterator::DEBUG,
	'h|help' => sub { usage() }
) or usage();

my ($ip,$sender,$helo,$local) = @ARGV;
($ip && $sender) or usage();

#### SPF lookup
my $spf = Mail::SPF::Iterator->new( $ip,$sender,$helo || '',$local );
my @rv = $spf->lookup_blocking;
print $spf->mailheader( @rv ),"\n";

#### USAGE
sub usage { die <<USAGE; }

 Usage: $0 [-d|--debug] Ip Sender [Helo] [Localname]
 lookup SPF result, returns SPF-Received header
 Example: 
 $0 10.0.3.4 user\@example.com smtp.example.com smtp.example.local

USAGE

