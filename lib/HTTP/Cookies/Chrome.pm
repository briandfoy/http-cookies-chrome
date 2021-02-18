use 5.010;
use utf8;

package HTTP::Cookies::Chrome;
use strict;

use warnings;
use warnings::register;

use POSIX;

=encoding utf8

=head1 NAME

HTTP::Cookies::Chrome - Cookie storage and management for Google Chrome

=head1 SYNOPSIS

	use HTTP::Cookies::Chrome;

	my $password = HTTP::Cookies::Chrome->get_from_gnome;

	my $cookie_jar = HTTP::Cookies::Chrome->new(
		chrome_safe_storage_password => $password,
		file     => ...,
		autosave => ...,
		);
	$cookie_jar->load( $path_to_cookies );

	# otherwise same as HTTP::Cookies

=head1 DESCRIPTION

This package overrides the C<load()> and C<save()> methods of
C<HTTP::Cookies> so it can work with Google Chrome cookie files,
which are SQLite databases. This also should work from Chrome clones,
such as Brave.

First, you are allowed to create different profiles within Chrome, and
each profile has its own set of files. The default profile is just C<Default>.
Along with that, there are various clones with their own product names.
The expected paths incorporate the product and profiles:

Starting with Chrome 80, cookie values may be (likely are) encrypted
with a password that Chrome changes and stores somewhere. Additionally,
each cookie record tracks several other fields. If you are
using an earlier Chrome, you should use an older version of this module
(the 1.x series).

=over 4

=item macOS - ~/Library/Application Support/PRODUCT/Chrome/PROFILE/Cookies

=item Linux - ~/.config/PRODUCT/PROFILE/Cookies

=item Windows - C:\Users\USER\AppData\Local\PRODUCT\User Data\$profile\Cookies

=back

The F<Cookies> file is an SQLite database.

=head2 Getting the Chrome Safe Storage password

You can get the Chrome Safe Storage password, although you may have to
respond to other dialogs and features of its storage mechanism:

On macOS:

	% security find-generic-password -a "Chrome" -w
	% security find-generic-password -a "Brave" -w

On Ubuntu using libsecret:

	% secret-tool lookup xdg:schema chrome_libsecret_os_crypt_password application chrome
	% secret-tool lookup xdg:schema chrome_libsecret_os_crypt_password application brave

If you know of other methods, let me know.

=head2 Environment

=over 4

=item * CHROME_PROFILE

The basic profile is C<Default>. If you have something else, set this environment variable.

=item * CHROME_SAFE_STORAGE_PASSWORD

Set this to the Chrome Safe Storage Password if there's not another way
to do it internally.

On macOS, this module can retrieve this with C<security find-generic-password -a "Chrome" -w>.

On Linux systems not using a keychain, the password might be C<peanut>
or C<mock_password>. Maybe I should use L<Passwd::Keyring::Gnome>

L<https://rtfm.co.ua/en/chromium-linux-keyrings-secret-service-passwords-encryption-and-store/>

L<https://stackoverflow.com/questions/57646301/decrypt-chrome-cookies-from-sqlite-db-on-mac-os>

L<https://superuser.com/a/969488/12972>


=back

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


sub _add_value {
	my( $self, $key, $value ) = @_;
	$self->_stash->{$key} = $value;
	}

sub _cipher { $_[0]->_get_value( 'cipher' ) }

sub _connect {
	my( $self, $file ) = @_;
	my $dbh = DBI->connect( "dbi:SQLite:dbname=$file", '', '',
		{
		sqlite_see_if_its_a_number => 1,
		} );
	$_[0]->{dbh} = $dbh;
	}

sub _dbh { $_[0]->{dbh} }

sub _decrypt {
	my( $self, $blob ) = @_;

	unless( $self->_cipher ) {
		warnings::warn("Decrypted cookies is not set up") if warnings::enabled();
		return;
		}

	my $type = substr $blob, 0, 3;
	unless( $type eq 'v10' ) { # v11 is a thing, too
		warnings::warn("Encrypted value is unexpected type <$type>") if warnings::enabled();
		return;
		}

	my $plaintext = $self->_cipher->decrypt( substr $blob, 3 );
	my $padding_count = ord( substr $plaintext, -1 );
	substr( $plaintext, -$padding_count ) = '' if $padding_count < 16;

	$plaintext;
	}

sub _get_rows {
	my( $self, $file ) = @_;

	my $dbh = $self->_connect( $file );

	my $sth = $dbh->prepare( 'SELECT * FROM cookies' );

	$sth->execute;

	my @rows =
		map {
			if( my $e = $_->encrypted_value ) {
			my $p = $self->_decrypt( $e );
				$_->decrypted_value( $self->_decrypt( $e ) );
				}
			$_;
			}
		map { HTTP::Cookies::Chrome::Record->new( $_ ) }
		@{ $sth->fetchall_arrayref };

	$dbh->disconnect;

	\@rows;
	}

sub _get_value {
	my( $self, $key ) = @_;
	$self->_stash->{$key}
	}

sub _make_cipher {
	my( $self, $password ) = @_;

	my $key = do {
		state $rc2 = require PBKDF2::Tiny;
		my $s = _platform_settings();
		my $salt = 'saltysalt';
		my $length = 16;
		PBKDF2::Tiny::derive( 'SHA-1', $password, $salt, $s->{iterations}, $length );
		};

	state $rc1 = require Crypt::Rijndael;
	my $cipher = Crypt::Rijndael->new( $key, Crypt::Rijndael::MODE_CBC() );
	$cipher->set_iv( ' ' x 16 );

	$self->_add_value( chrome_safe_storage_password => $password );
	$self->_add_value( cipher => $cipher );
	}

sub _platform_settings {
# https://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
# https://github.com/n8henrie/pycookiecheat/issues/12
	state $settings = {
		darwin => {
			iterations => 1003,
			},
		linux => {
			iterations => 1,
			},
		MSWin32 => {
			},
		};

	$settings->{$^O};
	}

sub _stash {
	state $mod_key = 'X-CHROME';
	state $hash = do { $_[0]->{$mod_key} = {} };
	$hash;
	}

sub new {
	my( $class, %args ) = @_;

	my $pass = delete $args{chrome_safe_storage_password};
	my $self = $class->SUPER::new( %args );

	return $self unless defined $pass;

	$self->_make_cipher( $pass );

	return $self;
	}

sub load {
	my( $self, $file ) = @_;

	$file ||= $self->{'file'} || return;

# $cookie_jar->set_cookie( $version, $key, $val, $path,
# $domain, $port, $path_spec, $secure, $maxage, $discard, \%rest )

	foreach my $row ( @{ $self->_get_rows( $file ) } ) {
		my $value = length $row->value ? $row->value : $row->decrypted_value;

		$self->set_cookie(
			undef,              # version
			$row->name,         # key
			$value,             # value
			$row->path,         # path
			$row->host_key,     # domain
			$row->source_port,  # port
			undef,              # path spec
			$row->is_secure,    # secure
			($row->expires_utc / 1_000_000) - time, # max_age
			0,                  # discard
			{
			map { $_ => $row->$_() } qw(
				creation_utc
				is_httponly
				last_access_utc
				has_expires
				is_persistent
				priority
				encrypted_value
				samesite
				source_scheme
				is_same_party)
			}
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
	decrypted_value
	);

sub new {
	my( $class, $array ) = @_;
	bless $array, $class;
	}

sub decrypted_value {
	my( $self, $value ) = @_;

	return $self->[ $columns{decrypted_value} ] unless defined $value;
	$self->[ $columns{decrypted_value} ] = $value;
	}

sub AUTOLOAD {
	my( $self ) = @_;
	my $method = $AUTOLOAD;
	$method =~ s/.*:://;

	die "No method <$method>" unless exists $columns{$method};

	$self->[ $columns{$method} ];
	}

sub DESTROY { 1 }
}


1;
