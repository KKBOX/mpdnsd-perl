use Test::MockObject;
use Test::More;

use mpdnsd;

mpdnsd::init_getopt();
$mpdnsd::querylog = Test::MockObject->new->set_true('write');

$dn = 'test.kkcube.com.r2.xxx.kkcube.com';
$query = Net::DNS::Packet->new($dn, 'A', 'IN');
($rcode, $ans, $auth, $add, $opt) = mpdnsd::reply_handler($dn, 'IN', 'A', '127.0.0.1', $query, $conn);
is($rcode, 'REFUSED', 'invalid service domain');

done_testing();
