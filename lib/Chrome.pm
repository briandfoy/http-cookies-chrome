use 5.010;
use utf8;

package HTTP::Cookies::Chrome;
use strict;

use warnings;
no warnings;

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

See L<HTTP::Cookies>.

=head1 The Chrome cookies table

	creation_utc    INTEGER NOT NULL UNIQUE PRIMARY KEY
	host_key        TEXT NOT NULL
	name            TEXT NOT NULL
	value           TEXT NOT NULL
	path            TEXT NOT NULL
	expires_utc     INTEGER NOT NULL
	secure          INTEGER NOT NULL
	httponly        INTEGER NOT NULL
	last_access_utc INTEGER NOT NULL

=head1 SOURCE AVAILABILITY

This module is in Github:

	http://github.com/briandfoy/HTTP-Cookies-Chrome

=head1 AUTHOR

brian d foy, C<< <bdfoy@cpan.org> >>

=head1 CREDITS

Jon Orwant pointed out the problem with dates too far in the future

=head1 COPYRIGHT AND LICENSE

Copyright (c) 2009-2010 brian d foy.  All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut


use base qw( HTTP::Cookies );
use vars qw( $VERSION );

use constant TRUE  => 'TRUE';
use constant FALSE => 'FALSE';

$VERSION = '1.01';

use Data::Dumper;
use DBI qw(:sql_types);

sub _get_rows
	{
	my( $self, $file ) = @_;
	
	my $dbh = DBI->connect( "dbi:SQLite:dbname=$file", '', '' );
	
	my $sth = $dbh->prepare( 'SELECT * FROM cookies' );

	# Without this, Perl converts the long numbers into
	# scientific notation
	foreach my $column ( 1, 6 .. 9 )
		{
		$sth->bind_col( $column, undef, SQL_INTEGER );
		}
		
	$sth->execute;
	
	my @rows = map { bless $_, 'HTTP::Cookies::Chrome::Record' }
		@{ $sth->fetchall_arrayref };
	
	#print STDERR Dumper( \@rows );
	
	\ @rows;
	}
	
sub load
	{
    my( $self, $file ) = @_;

    $file ||= $self->{'file'} || return;

# $cookie_jar->set_cookie( $version, $key, $val, $path, 
# $domain, $port, $path_spec, $secure, $maxage, $discard, \%rest )

 	foreach my $row ( @{ $self->_get_rows( $file ) } )
    	{
		$self->set_cookie(
			undef, 
			$row->name,
			$row->value,
			$row->path,
			$row->host_key,
			undef,
			undef,
			$row->secure,
			$row->expires_utc / 100_000 - gmtime, 
			0,
			{}
			);
    	}


    1;
	}

sub save
	{
    my( $self, $file ) = @_;

    $file ||= $self->{'file'} || return;
	
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
	secure          
	httponly        
	last_access_utc 
	);
	
sub AUTOLOAD
	{
	my( $self ) = @_;
	my $method = $AUTOLOAD;
	$method =~ s/.*:://;
	
	die "" unless exists $columns{$method};
	
	$self->[ $columns{$method} ];
	}

}

1;
