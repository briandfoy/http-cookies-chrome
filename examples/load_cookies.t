#!perl
use v5.10;

use File::FindLib qw(lib);
use Mojo::Util qw(dumper);

use HTTP::Cookies::Chrome;

my $path_to_cookies = '/Users/brian/Library/Application Support/Google/Chrome/Default/Cookies';

my $cookie_jar = HTTP::Cookies::Chrome->new;
$cookie_jar->load( $path_to_cookies );

say dumper( $cookie_jar );
