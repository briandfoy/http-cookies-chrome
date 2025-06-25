use v5.10;
use strict;
use warnings;

use DBI;
use File::Spec::Functions;

my $dir = 'test-corpus';
my $crypt_key = '1fFTtVFyMq/J03CMJvPLDg==';
my $v13_file = $ARGV[0] // catfile( $dir, 'cookies.db' );
my $v24_file = $ARGV[1] // catfile( $dir, 'cookies-v24.db' );

my $dbh_v13 = DBI->connect('dbi:SQLite:dbname=' . $v13_file);
my $dbh_v24 = DBI->connect('dbi:SQLite:dbname=' . $v24_file);
$dbh_v24->do( 'DELETE FROM cookies' );

my $sth = $dbh_v13->prepare( 'SELECT * FROM cookies' );
my $rc  = $sth->execute;

my @columns = qw(
	creation_utc
	host_key
	top_frame_site_key
	name
	value
	encrypted_value
	path
	expires_utc
	is_secure
	is_httponly
	last_access_utc
	has_expires
	is_persistent
	priority
	samesite
	source_scheme
	source_port
	last_update_utc
	source_type
	has_cross_site_ancestor
	);

my $columns = join ', ', @columns;
my $placeholders = join ', ', ('?') x @columns;
my $insert_sth = $dbh_v24->prepare( "INSERT INTO cookies ($columns) VALUES ($placeholders)" );

while( my $row = $sth->fetchrow_hashref ) {
	state %defaults = (
		top_frame_site_key      => '',
		last_update_utc         => time,
		source_type             => 0,
		has_cross_site_ancestor => 0,
		);

	my %computed;
	my $blob = $row->{encrypted_value};
    my $type = substr $blob, 0, 3, '';
	my $value = decrypt_v13($blob);

	$row->{encrypted_value} = encrypt_v24( $value, $row->{host_key} );

	my %hash = ( %defaults, $row->%* );
	dumper(\%hash);

	my $rc = $insert_sth->execute( @hash{@columns} );
	}

sub decrypt_v13 {
	my( $value ) = @_;
	state $cipher = _make_cipher($crypt_key);

	$cipher->decrypt($value);
	}

sub dumper { state $r = require Data::Dumper; say Data::Dumper->new([@_])->Indent(1)->Sortkeys(1)->Terse(1)->Useqq(1)->Dump }

sub encrypt_v24 {
	my( $plaintext, $host ) = @_;
	state $cipher = _make_cipher($crypt_key);

	state $rc = require Digest::SHA;

	$plaintext = Digest::SHA::sha256($host) . $plaintext;

	my $blocksize = 16;

	my $padding_length = ($blocksize - length($plaintext) % $blocksize);
	my $padding = chr($padding_length) x $padding_length;

	my $encrypted = 'v10' . $cipher->encrypt( $plaintext . $padding );
	}

sub _make_cipher {
	my( $password ) = @_;

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

	$cipher;
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
