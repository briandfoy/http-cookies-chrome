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

my $cookies = $cookie_jar->{COOKIES};
foreach my $site ( keys $cookies->%* ) {
	my $sites = $cookies->{$site};
	say $site;
	foreach my $path ( keys $sites->%* ) {
		my $names = $sites->{$path};
		say "  $path";
		foreach my $name ( keys $names->%* ) {
			my $value = $names->{$name}[1];
			printf "    %-16s %s\n", $name, $value;
			}
		}
	}

# say dumper( $cookie_jar );
