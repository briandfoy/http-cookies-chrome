use Test::More;
eval "use Test::Pod::Coverage 1.00";
all_pod_coverage_ok(
	{ also_private => [ qr/\A[_A-Z]+\z/ ], },
	);

