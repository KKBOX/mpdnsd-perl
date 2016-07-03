package mpdnsd;

BEGIN {
    *CORE::GLOBAL::fork = sub {
        $main::fork_ret;
    };

    *CORE::GLOBAL::sleep = sub {
        die;
    }
}

package main;

use Test::Exception;
use Test::MockObject;
use Test::MockModule;
use Test::More;

use mpdnsd;

our $fork_ret = 0;
my $getopt = Test::MockModule->new('main', no_auto => 1);
$getopt->mock('getopts' => undef);

my $sys = Test::MockModule->new('Sys::Syslog');
$sys->mock('closelog' => undef);
$sys->mock('openlog' => undef);
$sys->mock('syslog' => undef);

my $geoip = Test::MockModule->new('Geo::IP');
$geoip->mock('open' => undef);

my $rotate = Test::MockModule->new('File::Write::Rotate');
$rotate->mock('new' => undef);

my $dns = Test::MockModule->new('Net::DNS::Nameserver');
$dns->mock('new' => sub { Test::MockObject->new->set_true('main_loop'); });

mpdnsd::init_getopt();

ok(mpdnsd::run() || 1, 'call run()');
$mpdnsd::querylog_file = '';
ok(mpdnsd::reload() || 1, 'reload (w/ querylog_file)');

$fork_ret = 1;
dies_ok(sub { mpdnsd::run(); }, 'infinite loop');

$fork_ret = 0;
$mpdnsd::cpu = 2;
ok(mpdnsd::run() || 1, 'call run() w/ opts');
$mpdnsd::cpu = 1;

my $dns = Test::MockModule->new('Net::DNS::Nameserver')->mock('new');
dies_ok(sub { mpdnsd::run(); }, 'unable to new Net::DNS::Nameserver');

done_testing();
