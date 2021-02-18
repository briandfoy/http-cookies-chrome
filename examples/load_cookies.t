#!perl
use v5.10;
use strict;
use warnings;

use File::FindLib qw(lib);
use Mojo::Util qw(dumper);

use HTTP::Cookies::Chrome;

my $path_to_cookies = '/Users/brian/Library/Application Support/Google/Chrome/Default/Cookies';

# macOS
my $pass = `security find-generic-password -a "Chrome" -w`;
chomp($pass);

my $cookie_jar = HTTP::Cookies::Chrome->new(
	chrome_safe_storage_password => $pass
	);
$cookie_jar->load( $path_to_cookies );

say dumper( $cookie_jar );
