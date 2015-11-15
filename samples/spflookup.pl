#!/usr/bin/perl
use strict;
use warnings;
use Mail::SPF::Iterator;
#use Mail::SPF::Iterator DebugFunc => \&DEBUG;
use Getopt::Long qw(:config posix_default bundling);

#### Options
GetOptions(
    'd|debug' => sub { Mail::SPF::Iterator->import( Debug => 1 ) },
    'h|help' => sub { usage() }
) or usage();

my ($ip,$sender,$helo,$local) = @ARGV;
($ip && $sender) or usage();

#### SPF lookup
my $spf = Mail::SPF::Iterator->new( $ip,$sender,$helo || '',$local );
my $result = $spf->lookup_blocking;
print "Received-SPF: ".$spf->mailheader."\n";
print "Explanation: ".($spf->result)[3]."\n" if $result eq SPF_Fail;


#### USAGE
sub usage { die <<USAGE; }

 Usage: $0 [-d|--debug] Ip Sender [Helo] [Localname]
 lookup SPF result, returns SPF-Received header
 Example: 
 $0 10.0.3.4 user\@example.com smtp.example.com smtp.example.local

USAGE

sub DEBUG {
    print STDERR "DEBUG: @_\n";
}

