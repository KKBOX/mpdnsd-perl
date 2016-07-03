#!/usr/bin/env perl

package mpdnsd;

use 5.010;
use integer;
use strict;
use warnings;

use File::Basename;
use File::Write::Rotate;
use Geo::IP;
use Getopt::Long;
use Net::DNS;
use Net::DNS::Packet;
use Net::DNS::Nameserver;
use Net::DNS::RR;
use Sys::Syslog qw/:macros :standard/;

our ($asnip, $bind_host, $cpu, $geoip, $nsrrs, %opts, $port, $querylog, $querylog_file, $service_domain, $ttl, $ttl_asn, $ttl_country, $ttl_ns, $ttl_random, $whitelist_domain);

sub init_getopt {
    $bind_host = '127.0.0.1';
    $cpu = 1;
    $nsrrs = 'mpns1.kkcube.com,mpns2.kkcube.com,mpns3.kkcube.com';
    $port = 53;
    $service_domain = 'mp.kkcube.com';
    $ttl = 20;
    $ttl_asn = 43200;
    $ttl_country = 43200;
    $ttl_ns = 43200;
    $ttl_random = 20;
    $whitelist_domain = 'kfs.io,kkbox.com,kkbox.com.tw,kkcube.com';
}

sub run {
    init_getopt();

    GetOptions(
        'bind_host|h=s' => \$bind_host,
        'cpu|c=i' => \$cpu,
        'nsrrs|r=s' => \$nsrrs,
        'port|p=i' => \$port,
        'querylog_file|q=s' => \$querylog_file,
        'service_domain|s=s' => \$service_domain,
        'ttl|t=i' => \$ttl,
        'ttl_asn=i' => \$ttl_asn,
        'ttl_country=i' => \$ttl_country,
        'ttl_ns=i' => \$ttl_ns,
        'ttl_random=i' => \$ttl_random,
        'whitelist_domain=s' => \$whitelist_domain,
    );

    my $ns = Net::DNS::Nameserver->new(
        LocalAddr => [split /,+/, $bind_host],
        LocalPort => $port,
        ReplyHandler => \&reply_handler,
    ) or die $!;

    reload();
    $SIG{HUP} = \&reload;

    patch_edns();

    while ($cpu--) {
        fork && last;
    }

    infinite_loop() if 0 == $cpu;

    $ns->main_loop;
}

sub infinite_loop {
    for (;;) {
        sleep 1;
    }
}

sub patch_edns {
    # Monkey patch
    no warnings;

    *Net::DNS::Packet::edns = sub {
        my $self = shift;
        my $link = \$self->{xedns};
        ($$link) = grep $_->isa(qw(Net::DNS::RR::OPT)), @{$self->{additional}};
        $$link = new Net::DNS::RR(type => 'OPT') unless $$link;
    };
}

sub reload {
    closelog;
    openlog 'mpdnsd', 'pid', 'daemon';
    syslog LOG_NOTICE, 'syslogd reloaded';

    $geoip = Geo::IP->open('/usr/share/GeoIP/GeoIP.dat', GEOIP_STANDARD);
    syslog LOG_NOTICE, 'GeoIP.dat reloaded';

    $asnip = Geo::IP->open('/usr/share/GeoIP/GeoIPASNum.dat', GEOIP_STANDARD);
    syslog LOG_NOTICE, 'GeoIPASNum.dat reloaded';

    if (defined $querylog_file) {
        $querylog = File::Write::Rotate->new(
            dir => dirname($querylog_file),
            prefix => basename($querylog_file),
            size => 100 * 1024 * 1024,
            histories => 10,
        );
    }
}

sub reply_handler {
    my ($qname, $qclass, $qtype, $peerhost, $query, $conn) = @_;

    my $now = localtime;
    $querylog->write("${now}: Receiving request from ${peerhost}: ${qname} ${qclass} ${qtype}\n") if $querylog;

    my (@add, @ans, @auth, $service, $suffix);

    if (lc($qname) eq $service_domain) {
        foreach my $nsrr (split /,+/, $nsrrs) {
            push @ans, Net::DNS::RR->new("${service_domain} ${ttl_ns} IN NS ${nsrr}");
        }
        return ('NOERROR', \@ans, \@auth, \@add, {aa => 1});
    }

    # Validate service domain.
    if (lc($qname) =~ /^(.+)\.(\w+)\.\Q${service_domain}\E$/) {
        $suffix = $1;
        $service = $2;
    } else {
        return ('REFUSED', \@ans, \@auth, \@add, {aa => 1});
    }

    # Valid suffix domain.
    foreach my $domain (split /,+/, $whitelist_domain) {
        if (lc($suffix) =~ /\.\Q${domain}\E$/) {
            goto VALID;
        }
    }

    return ('REFUSED', \@ans, \@auth, \@add, {aa => 1});
VALID:

    my $rcode = 'SERVFAIL';

    eval {
        my $ip = $peerhost;

        # edns-client-subnet support
        do {{
            my $edns_opt = $query->header->edns->option(8);
            next unless defined $edns_opt;

            if (1 != unpack 'n', substr($edns_opt, 0, 2)) {
                $rcode = 'FORMERR';
                return;
            }

            if (0 != unpack 'C', substr($edns_opt, 3, 1)) {
                $rcode = 'FORMERR';
                return;
            }

            my $cidr = unpack 'C', substr($edns_opt, 2, 1);
            my $opt = Net::DNS::RR->new(
                type => 'OPT',
                flags => 0,
                rcode => 0,
            );
            substr($edns_opt, 3, 1) = chr(24);
            $opt->option(8 => $edns_opt);
            push @add, $opt;

            last if 24 > $cidr;

            my $ip_raw = substr($edns_opt, 4, 4);
            $ip = join '.', unpack 'C4', $ip_raw . "\0\0\0\0";
        }} while (0);

        if ('asn' eq lc($service)) {
            my $asn = $asnip->isp_by_addr($ip) // '';
            if ($asn =~ /^AS(\d+) /) {
                $asn = $1;
            } else {
                $asn = 'default';
            }

            my $rr = Net::DNS::RR->new("${qname} ${ttl_asn} IN CNAME ${asn}.${suffix}");
            push @ans, $rr;
            $rcode = 'NOERROR';
            return;
        }

        if ('country' eq lc($service)) {
            my $cc = $geoip->country_code_by_addr($ip) // 'default';
            my $rr = Net::DNS::RR->new("${qname} ${ttl_country} IN CNAME ${cc}.${suffix}");
            push @ans, $rr;
            $rcode = 'NOERROR';
            return;
        }

        if ($service =~ /r(\d+)/i) {
            my $num = int rand int $1;
            my $rr = Net::DNS::RR->new("${qname} ${ttl_random} IN CNAME ${num}.${suffix}");
            push @ans, $rr;
            $rcode = 'NOERROR';
            return;
        }

        $rcode = 'NXDOMAIN';
    };

    foreach my $nsrr (split /,+/, $nsrrs) {
        push @add, Net::DNS::RR->new("${service_domain} ${ttl_ns} IN NS ${nsrr}");
    }

    return ($rcode, \@ans, \@auth, \@add, {aa => 1});
}

__PACKAGE__->run(@ARGV) unless caller();

__END__

=head1 NAME

mpdnsd - Marco Polo DNS Daemon

=head1 SYNOPSIS

mpdnsd [--bind_host IP1,IP2,...] [--cpu CPU] [--nsrrs NS1.DOMAIN,NS2.DOMAIN,...] [--port PORT] [--querylog_file FILENAME] [--server_domain SERVICE.DOMAIN] [--ttl_asn SECONDS] [--ttl_country SECONDS][--ttl_ns SECONDS] [--ttl_random SECONDS]

=head1 DESCRIPTION

Macro Polo is a DNS server, which can answer AS number and country info by CNAME record according to client's IP address and edns-client-subnet information.  Also, it can answer a number randomly.

You can use this DNS daemon to mix different cache servers and CDNs.

=head1 USAGE

When service_domain is C<mp.example.com>, use this query:

    Q: test.example.com.asn.mp.example.com

It will strip service domain part, and prepend AS number of client to it, like:

    A: 12345.test.example.com

And C<country> will prepend country code:

    Q: test.example.com.country.mp.example.com
    A: TW.test.example.com

And C<r> + number will return a number of this range randomly.

    Q: test.example.com.r10.mp.example.com
    A: 9.test.example.com

In this sample, it will return [0-9].test.example.com because range is [0..10).

=head1 AUTHOR

Gea-Suan Lin E<lt>gslin@kkbox.comE<gt>

=cut
