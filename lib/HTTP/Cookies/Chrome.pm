use 5.010;
use utf8;

package HTTP::Cookies::Chrome;
use strict;

use warnings;
no warnings;

use POSIX;

=encoding utf8

=head1 NAME

HTTP::Cookies::Chrome - Cookie storage and management for Google Chrome

=head1 SYNOPSIS

	use HTTP::Cookies::Chrome;

	my $cookie_jar = HTTP::Cookies::Chrome->new;
	$cookie_jar->load( $path_to_cookies );

	# otherwise same as HTTP::Cookies

=head1 DESCRIPTION

This package overrides the C<load()> and C<save()> methods of
C<HTTP::Cookies> so it can work with Google Chrome cookie files,
which are SQLite databases.

NOTE: This does not handle encrypted cookies files yet (https://github.com/briandfoy/HTTP-Cookies-Chrome/issues/1).

See L<HTTP::Cookies>.

=head2 The Chrome cookies table

	creation_utc    INTEGER NOT NULL UNIQUE PRIMARY KEY
	host_key        TEXT NOT NULL
	name            TEXT NOT NULL
	value           TEXT NOT NULL
	path            TEXT NOT NULL
	expires_utc     INTEGER NOT NULL
	is_secure       INTEGER NOT NULL
	is_httponly     INTEGER NOT NULL
	last_access_utc INTEGER NOT NULL
	has_expires     INTEGER NOT NULL
	is_persistent   INTEGER NOT NULL
	priority        INTEGER NOT NULL
	encrypted_value BLOB
	samesite        INTEGER NOT NULL
	source_scheme   INTEGER NOT NULL
	source_port     INTEGER NOT NULL
	is_same_party   INTEGER NOT NULL

=head1 SOURCE AVAILABILITY

This module is in Github:

	https://github.com/briandfoy/http-cookies-chrome

=head1 AUTHOR

brian d foy, C<< <bdfoy@cpan.org> >>

=head1 CREDITS

Jon Orwant pointed out the problem with dates too far in the future

=head1 COPYRIGHT AND LICENSE

Copyright © 2009-2021, brian d foy <bdfoy@cpan.org>. All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms of the Artistic License 2.0.

=cut


use base qw( HTTP::Cookies );
use vars qw( $VERSION );

use constant TRUE  => 1;
use constant FALSE => 0;

$VERSION = '2.001';

use DBI;

sub _dbh { $_[0]->{dbh} }

sub _connect {
	my( $self, $file ) = @_;
	my $dbh = DBI->connect( "dbi:SQLite:dbname=$file", '', '',
		{
		sqlite_see_if_its_a_number => 1,
		} );
	$_[0]->{dbh} = $dbh;
	}

sub _get_rows {
	my( $self, $file ) = @_;

	my $dbh = $self->_connect( $file );

	my $sth = $dbh->prepare( 'SELECT * FROM cookies' );

	$sth->execute;

	my @rows = map { bless $_, 'HTTP::Cookies::Chrome::Record' }
		@{ $sth->fetchall_arrayref };

	$dbh->disconnect;

	\ @rows;
	}

sub load {
	my( $self, $file ) = @_;

	$file ||= $self->{'file'} || return;

# $cookie_jar->set_cookie( $version, $key, $val, $path,
# $domain, $port, $path_spec, $secure, $maxage, $discard, \%rest )

	foreach my $row ( @{ $self->_get_rows( $file ) } ) {

		my $value = length $row->value ? $row->value : $row->decrypted_value;

		$self->set_cookie(
			undef,
			$row->name,
			$value,
			$row->path,
			$row->host_key,
			undef,
			undef,
			$row->is_secure,
			($row->expires_utc / 1_000_000) - gmtime,
			0,
			{}
			);
		}

	1;
	}

sub save {
    my( $self, $new_file ) = @_;

    $new_file ||= $self->{'file'} || return;

	my $dbh = $self->_connect( $new_file );

	$self->_create_table;
	$self->_prepare_insert;
	$self->_filter_cookies;
	$dbh->disconnect;

	1;
	}

sub _filter_cookies {
    my( $self ) = @_;

    $self->scan(
		sub {
			my( $version, $key, $val, $path, $domain, $port,
				$path_spec, $secure, $expires, $discard, $rest ) = @_;

				return if $discard && not $self->{ignore_discard};

				return if defined $expires && time > $expires;

				$expires = do {
					unless( $expires ) { 0 }
					else {
						$expires * 1_000_000
						}
					};

				$secure = $secure ? TRUE : FALSE;

				my $bool = $domain =~ /^\./ ? TRUE : FALSE;

				$self->_insert(
					$domain,
					$key,
					$val,
					$path,
					$expires,
					$secure,
					);
			}
		);

	}

sub _create_table {
	my( $self ) = @_;

	$self->_dbh->do(  'DROP TABLE IF EXISTS cookies' );

	$self->_dbh->do( <<'SQL' );
CREATE TABLE cookies(
	creation_utc    INTEGER NOT NULL,
	host_key        TEXT NOT NULL,
	name            TEXT NOT NULL,
	value           TEXT NOT NULL,
	path            TEXT NOT NULL,
	expires_utc     INTEGER NOT NULL,
	is_secure       INTEGER NOT NULL,
	is_httponly     INTEGER NOT NULL,
	last_access_utc INTEGER NOT NULL,
	has_expires     INTEGER NOT NULL DEFAULT 1,
	is_persistent   INTEGER NOT NULL DEFAULT 1,
	priority        INTEGER NOT NULL DEFAULT 1,
	encrypted_value BLOB DEFAULT '',
	samesite        INTEGER NOT NULL DEFAULT -1,
	source_scheme   INTEGER NOT NULL DEFAULT 0,
	source_port     INTEGER NOT NULL DEFAULT -1,
	is_same_party   INTEGER NOT NULL DEFAULT 0,
	UNIQUE (host_key, name, path)
	)
SQL
	}

sub _prepare_insert {
	my( $self ) = @_;

	my $sth = $self->{insert_sth} = $self->_dbh->prepare_cached( <<'SQL' );
INSERT INTO cookies VALUES
	(
	?,
	?, ?, ?, ?,
	?,
	?,
	?,
	?
	)
SQL

	}

{
my $creation_offset = 0;

sub _insert {
	my( $self,
		$domain, $key, $value, $path, $expires, $secure, ) = @_;

	my $sth = $self->{insert_sth};

	my $creation    = $self->_get_utc_microseconds( $creation_offset++ );

	my $last_access = $self->_get_utc_microseconds;
	my $httponly    = 0;

	$sth->execute(
		$creation,      # 1
		$domain,        # 2
		$key,           # 3
		$value,         # 4
		$path,          # 5
		$expires,       # 6
		$secure,        # 7
		$httponly,      # 8
		$last_access,   # 9
		);

	}
}

sub _get_utc_microseconds {
	no warnings 'uninitialized';
	use bignum;
	POSIX::strftime( '%s', gmtime() ) * 1_000_000 + ($_[1]//0);
	}

BEGIN {
package HTTP::Cookies::Chrome::Record;
use vars qw($AUTOLOAD);

my %columns = map { state $n = 0; $_, $n++ } qw(
	creation_utc
	host_key
	name
	value
	path
	expires_utc
	is_secure
	is_httponly
	last_access_utc
	has_expires
	is_persistent
	priority
	encrypted_value
	samesite
	source_scheme
	source_port
	is_same_party
	);

sub AUTOLOAD {
	my( $self ) = @_;
	my $method = $AUTOLOAD;
	$method =~ s/.*:://;

	die "No method <$method>" unless exists $columns{$method};

	$self->[ $columns{$method} ];
	}

sub DESTROY { 1 }

# https://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
# https://github.com/n8henrie/pycookiecheat/issues/12
sub platform_settings {
	state $settings = {
		darwin => {
			iterations => 1003,
			password   => do {
				my $p = $ENV{CHROME_SAFE_STORAGE_PASS} // `security find-generic-password -a "Chrome" -w`;
				chomp $p;
				$p;
				},
			},
		# https://github.com/n8henrie/pycookiecheat/issues/12
		linux => {
			iterations => 1,
			password   => $ENV{CHROME_SAFE_STORAGE_PASS},
			},
		windows => {
			password   => $ENV{CHROME_SAFE_STORAGE_PASS},
			},
		};
	my $profile = $ENV{CHROME_PROFILE} // 'Default';

	$settings->{darwin}{path}  = "$ENV{HOME}/Library/Application Support/Google/Chrome/$profile/Cookies";
	$settings->{linux}{path}   = "$ENV{HOME}/.config/chromium/$profile/Cookies";
	$settings->{windows}{path} = "C:\\Users\\<username>\\AppData\\Local\\Google\\Chrome\\User Data\\$profile\\Cookies";
	$settings->{darwin};
	}

sub decrypted_value {
	state $rc1 = require Crypt::Rijndael;
	state $rc2 = require PBKDF2::Tiny;
	state $key = do {
		my $s = platform_settings();
		say Dumper( $s ); use Data::Dumper;
		my $salt = 'saltysalt';
		my $length = 16;
		PBKDF2::Tiny::derive( 'SHA-1', $s->{password}, $salt, $s->{iterations}, $length );
		};
	state $cipher = do {
		my $c = Crypt::Rijndael->new( $key, Crypt::Rijndael::MODE_CBC() );
		$c->set_iv( ' ' x 16 );
		$c;
		};

	say "Length of value is " . length( $_[0]->encrypted_value );

	my $plaintext = $cipher->decrypt( substr $_[0]->encrypted_value, 3 );
	my $padding_count = ord( substr $plaintext, -1 );
	printf "Padding is %o\n", $padding_count;
	substr( $plaintext, -$padding_count ) = '';
	$plaintext;
	}
}

1;
