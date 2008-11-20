#!/usr/bin/perl
############################################################################
# THIS IS NOT A TEST!
# make *.pl from YAML test suite, so that we don't have YAML as a 
# requirement for our tests
############################################################################
use strict;
use warnings;
use Data::Dumper;
use YAML 'LoadFile';

my $src = 'rfc4408-tests.yml';
my $dst = 'rfc4408-tests.pl';
for (  '.','t' ) {
	-f "$_/$src" or next;
	my @tests = LoadFile( "$_/$src" );
	open( my $fh,'>', "$_/$dst" ) or die "write $_/$dst: $!";
	print $fh Data::Dumper->new([\@tests])->Terse(1)->Indent(1)->Dump;
	exit
}
die "could not convert YAML tests to pl: no YAML file found";
