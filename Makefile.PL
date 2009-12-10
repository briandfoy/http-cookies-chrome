use ExtUtils::MakeMaker;

require 5.008;

eval "use Test::Manifest 1.14";

WriteMakefile(
	'NAME'	       => 'HTTP::Cookies::Chrome',
	'ABSTRACT'     => 'This is what the module does',
	'VERSION_FROM' => 'lib/Chrome.pm',
	'LICENSE'      => 'perl',
	'AUTHOR'       => 'brian d foy <bdfoy@cpan.org>',
	
	'PREREQ_PM'    => { 
		'Test::More' => '0',
		},

	'PM'           => {
		'lib/Chrome.pm'         => '$(INST_LIBDIR)/Chrome.pm',
		},

	'MAN3PODS'     => {
		'lib/Chrome.pm' => '$(INST_MAN3DIR)/HTTP::Cookies::Chrome.3',
		},

	clean  => { FILES    => q|HTTP-Cookies-Chrome-*| },

	);
