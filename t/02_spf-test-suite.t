#!/usr/bin/perl
use strict;
use warnings;

my @tests;
BEGIN {
	eval 'use YAML "LoadFile"';
	if ( $@ ) {
		print "1..0 # YAML not installed: $@\n";
		exit;
	}
	my $tfile = 'rfc4408-tests.yml';
	for (  $tfile,"t/$tfile" ) {
		-f or next;
		@tests = LoadFile( $_ );
		last;
	}
	if ( ! @tests ) {
		print "1..0 # YAML file for test suite not found\n";
		exit;
	}
	my $sum = 0;
	$sum += keys(%{ $_->{tests} }) for (@tests);
	print "1..$sum\n";
}

use Mail::SPF::Iterator;
use Net::DNS;
use Data::Dumper;


$|=1;
my $DEBUG=1;

for my $test ( @tests ) {
	my $desc= $test->{description};
	my $dns_setup = $test->{zonedata};
	my $subtests = $test->{tests};

	my $resolver = myResolver->new( records => $dns_setup );
	for my $tname (sort keys %$subtests) {
		my $tdata = $subtests->{$tname};
		my $result = $tdata->{result};
		$result = [ $result ] if ! ref $result;
		$_=lc for(@$result);

		my $spec = $tdata->{spec};
		$spec = [ $spec ] if ! ref($spec);
		my $comment =  "$desc | $tname (@$spec) (@$result)";

		my $status = '';
		# capture debug output of failed cases
		my $debug = '';
		eval {
			open( my $dbg, '>',\$debug );
			local *STDERR = $dbg;

			my %d = %$tdata;
			my $spf = eval {
				Mail::SPF::Iterator->new(
					delete $d{host},
					delete $d{mailfrom},
					delete $d{helo},
				);
			};
			die "no spf: $@\n".Dumper($tdata) if ! $spf;

			($status, my @ans) = $spf->next;
			while ( ! $status ) {
				my ($cbid,@query) = @ans;
				die "no queries" if ! @query;
				for my $q (@query) {
					#DEBUG( "next query: ".$q->string );
					my $answer = $resolver->send( $q );
					($status,@ans) = $spf->next( $cbid,$answer 
						? $answer 
						: [ $q, $resolver->errorstring ]
					);
					DEBUG( "status=$status" ) if $status;
					last if $status or @ans;
				}
			}
			$status = lc($status);
			if ( ! grep { $status eq $_ } @$result ) {
				die "  .. got status=$status tdata=".Dumper($tdata)."ans=@ans\n";
			} elsif ( $status ne $result->[0] ) {
				if ( $tname =~m{^(mx|ptr)-limit$} ) {
					#### spec: "... The SPF result is effectively randomized."
					print "------- got $status, expected @$result\n";
				} else {
					die "------- got $status, expected @$result\n".Dumper($tdata);
				}
			}
		};
		if ( $@ ) {
			print "not ok # $comment - got $status\n";
			( my $t = "$debug\n$@" ) =~s{^}{| }mg;
			print $t;
		} elsif ( $status ne $result->[0] ) {
			print "ok # $comment - got $status\n";
		} else {
			print "ok # $comment\n";
		}
	}
}

############################################################################
# DEBUG
############################################################################

sub DEBUG {
	$DEBUG or return; # check against debug level
	my (undef,$file,$line) = caller;
	my $msg = shift;
	$file = '...'.substr( $file,-17 ) if length($file)>20;
	$msg = sprintf $msg,@_ if @_;
	print STDERR "DEBUG: $file:$line: $msg\n";
}

############################################################################
# myResolver
# implements Net::DNS::Resolver for tests, ideas stolen from
# Net::DNS::Resolver::Programmable
############################################################################

package myResolver;
use base 'Net::DNS::Resolver';
use Data::Dumper;

sub DEBUG { goto &::DEBUG }

sub new {
	my ($class,%options) = @_;
	my $self = $class->SUPER::new(%options);
	$self->{records} = $options{records};
	return $self;
}

sub send {
	my $self = shift;
	my $pkt = $self->make_query_packet(@_);
	my $q = ($pkt->question)[0];
	my $qname = lc($q->qname);
	my $qtype = $q->qtype;
	my $qclass = $q->qclass;

	$self->_reset_errorstring;

	DEBUG( "query=".$q->string );

	( my $key = $qname) =~s{\.$}{};
	if ( my @match = grep { lc($key) eq lc($_) } keys %{ $self->{records}} ) {
		my $rrdata = $self->{records}{$match[0]};

		my (%ans,$timeout);
		for my $data (@$rrdata) {
			if ( $data eq 'TIMEOUT' ) {
				# report as error
				$timeout = 1;
			} elsif ( ref($data) eq 'HASH' ) { ### { SPF => ... }
				# create and collect RR
				my @typ = keys %$data;
				@typ == 1 or die Dumper( $data ); # expect only 1 key
				push @{ $ans{$typ[0]}}, $data->{$typ[0]};
			}
		}

		$ans{TXT} ||= $ans{SPF};
		for (values %ans) {
			$_ = undef if $_ and @$_ == 1 and $_->[0] eq 'NONE';
		}
		my @answer = @{ $ans{$qtype} || []};

		if ( $timeout && ! @answer ) {
			$self->errorstring('TIMEOUT');
			return undef;
		}

		my @additional;
		for my $ans (@answer) {	
			my %rr = ( type => $qtype, name => $qname );
			if ( $qtype eq 'MX' ) {
				$rr{exchange} = $ans->[1];
				$rr{priority} = $ans->[0];
				# add A/AAAA records for MX name as additional data
				if ( my $add = $self->{records}{$ans->[1]} ) {
					for (@$add) {
						next if ! ref;
						my @k = keys %$_;
						next if @k != 1 or ( $k[0] ne 'A' and $k[0] ne 'AAAA' );
						push @additional, Net::DNS::RR->new( 
							name => $ans->[1],
							type => $k[0],
							address => $_->{$k[0]} 
						) or die;
						DEBUG( "additional: ".$additional[-1]->string );
					}
				}
			} elsif ( $qtype eq 'A' || $qtype eq 'AAAA' ) {
				$rr{address} = $ans
			} elsif ( $qtype eq 'SPF' || $qtype eq 'TXT' ) {
				$rr{char_str_list} = ref($ans) ? $ans : [ $ans ];
			} elsif ( $qtype eq 'PTR' ) {
				$rr{ptrdname} = $ans;
			} else {
				die $qtype
			}

			#DEBUG( Dumper( \%rr ));
			$ans = Net::DNS::RR->new( %rr ) or die;
			DEBUG( "answer: ".$ans->string );
		}

		# create answer packet
		my $packet = Net::DNS::Packet->new($qname, $qtype, $qclass);
		$packet->header->qr(1);
		$packet->header->rcode('NOERROR');
		$packet->header->aa(1);
		if ( @answer ) {
			$packet->push(answer => @answer);
			$packet->push(additional => @additional) if @additional;
		}
		return $packet;
	}

	# report that domain does not exist
	DEBUG( "send NXDOMAIN" );
	my $packet = Net::DNS::Packet->new($qname, $qtype, $qclass);
	$packet->header->qr(1);
	$packet->header->rcode('NXDOMAIN');
	$packet->header->aa(1);
	return $packet;
}

