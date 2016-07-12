use Test::MockObject;
use Test::More;

use mpdnsd;

my $asnip = Test::MockObject->new;
$asnip->set_series('isp_by_addr', undef, 'AS12345 ');

my $geoip = Test::MockObject->new;
$geoip->set_series('country_code_by_addr', undef, 'US');

mpdnsd::init_getopt();
$mpdnsd::asnip = $asnip;
$mpdnsd::geoip = $geoip;

my $conn = '';

my ($add, $ans, $auth, $dn, $opt, $query, $rcode);

mpdnsd::patch_edns();

$dn = 'test.kkcube.com.r2.xxx.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'REFUSED', 'invalid service domain');

$dn = 'invalid.com.r2.mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'REFUSED', 'invalid return domain');

$dn = 'mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'NS', 'IN');
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'NS', '127.0.0.1', $query, $conn);
is($rcode, 'NOERROR', 'nameserver');

$dn = 'test.kkcube.com.invalid.mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'NS', 'IN');
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'NS', '127.0.0.1', $query, $conn);
is($rcode, 'NXDOMAIN', 'invalid service');

$dn = 'test.kkcube.com.asn.mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'NOERROR', 'asn (default)');

$dn = 'test.kkcube.com.asn.mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'NOERROR', 'asn (AS12345)');

$dn = 'test.kkcube.com.country.mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'NOERROR', 'country (default)');

$dn = 'test.kkcube.com.country.mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'NOERROR', 'country (US)');

$dn = 'test.kkcube.com.hour.mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'NOERROR', 'hour');

$dn = 'test.kkcube.com.r2.mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'NOERROR', 'random');

$dn = 'test.kkcube.com.r2.mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
my $e = Net::DNS::RR->new(
    'type' => 'OPT',
);
$e->{option} = {
    8 => pack('nCCN', 0, 0, 0, 0),
};
$query->{additional} = [$e];
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'FORMERR', 'random (w/ malformed edns)');

$dn = 'test.kkcube.com.r2.mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
my $e = Net::DNS::RR->new(
    'type' => 'OPT',
);
$e->{option} = {
    8 => pack('nCCN', 1, 0, 1, 0),
};
$query->{additional} = [$e];
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'FORMERR', 'random (w/ another malformed edns)');

$dn = 'test.kkcube.com.r2.mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
my $e = Net::DNS::RR->new(
    'type' => 'OPT',
);
$e->{option} = {
    8 => pack('nCCN', 1, 24, 0, 0),
};
$query->{additional} = [$e];
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'NOERROR', 'random (w/ edns, /24)');

$dn = 'test.kkcube.com.r2.mp.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
my $e = Net::DNS::RR->new(
    'type' => 'OPT',
);
$e->{option} = {
    8 => pack('nCCN', 1, 16, 0, 0),
};
$query->{additional} = [$e];
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'NOERROR', 'random (w/ edns, /16)');

$dn = 'test.kkcube.com.r2.MP.KKCUBE.COM';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'NOERROR', 'uppercase MP.KKCUBE.COM');

done_testing();
