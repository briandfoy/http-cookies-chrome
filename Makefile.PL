require 5.010;
use strict;
use warnings;

my $github    = 'https://github.com/briandfoy/';
my $main_file = 'lib/HTTP/Cookies/Chrome.pm';

my %WriteMakefile = (
	'NAME'	        => 'HTTP::Cookies::Chrome',
	'ABSTRACT_FROM' => $main_file,
	'VERSION_FROM'  => $main_file,
	'LICENSE'       => 'perl',
	'AUTHOR'        => 'brian d foy <bdfoy@cpan.org>',
	
	'PREREQ_PM'    => { 
		'DBI'           => '0',
		'DBD::SQLite'   => '1.32',
		'POSIX'         => '0',
		'HTTP::Cookies' => '0',
		},

	'TEST_REQUIRES' => {
		'Test::More'  => '0.95',
		},

	'META_MERGE' => {
		'meta-spec' => { version => 2 },
		resources => {
			repository => {
				type => 'git',
				url  => 'https://github.com/briandfoy/HTTP-Cookies-Chrome.git',
				web  => 'https://github.com/briandfoy/HTTP-Cookies-Chrome',
				},
			bugtracker => {
				web  => 'https://github.com/briandfoy/HTTP-Cookies-Chrome/issues',
				},
			},
		},

	clean  => { FILES    => q|HTTP-Cookies-Chrome-*| },

	);

sub arguments { \%WriteMakefile }

do_it() unless caller;
sub do_it {
	require File::Spec;
	my $MM ='ExtUtils::MakeMaker';
	my $MM_version =
		eval{ "$MM " . $WriteMakefile{'CONFIGURE_REQUIRES'}{'ExtUtils::MakeMaker'} }
			//
		"$MM 6.64";
	eval "use $MM_version";
	eval "use Test::Manifest 1.21" 
		if -e File::Spec->catfile( qw(t test_manifest) );
	WriteMakefile( %WriteMakefile );
	}


no warnings;
__PACKAGE__;
