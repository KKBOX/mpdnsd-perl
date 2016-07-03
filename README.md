Marco Polo DNS Daemon
---------------------

Intro
-----

Marco Polo DNS Daemon is a DNS server, which can return different CNAME record based on DNS resolver's IP address and edns-client-subnet information.

Currently it supports three types: AS Number, Country Code, and Random.

Install
-------

Install the following dependencies:

* libfile-write-rotate-perl (File::Write::Rotate)
* libgeo-ip-perl (Geo::IP)
* libnet-dns-perl (Net::DNS) - Version 0.68 on Ubuntu 14.04 and eariler one are not new enough to work
* geoip-database-contrib

Then just copy `lib/mpdnsd.pm` into `/usr/sbin/mpdnsd`.

Run
---

    /usr/sbin/mpdnsd \
        [--bind_host IP1,IP2,...] \
        [--cpu CPU] \
        [--nsrrs NS1.DOMAIN,NS2.DOMAIN,...] \
        [--port PORT] \
        [--querylog_file FILENAME] \
        [--service_domain SERVICE.DOMAIN] \
        [--ttl_asn SECONDS] \
        [--ttl_country SECONDS] \
        [--ttl_ns SECONDS] \
        [--ttl_random SECONDS] \
        [--whitelist_domain ONE.MP.DOMAIN,TWO.MP.DOMAIN]

For example:

    /usr/sbin/mpdnsd \
        --bind_host 0.0.0.0 \
        --nsrrs mp-ns1.example.com,mp-ns2.example.com \
        --service_domain mp.example.com \
        --whitelist_domain example.com

Use
---

You can get AS number by this example:

    dig test.example.com.asn.mp.example.com @mp-ns1.example.com

It will return a CNAME record to:

    12345.test.example.com

Which `12345` is AS number based on client's DNS resolver or edns-client-subnet information.

Also, you can get country code:

    dig test.example.com.country.mp.example.com @mp-ns1.example.com
    TW.test.example.com

And you can choose randomly for range [0..10) (i.e. 0~9):

    dig test.example.com.r10.mp.example.com
    9.test.example.com

Test
----

    perl Build.PL
    ./Build testcover

License
-------
Copyright (c) 2016, Gea-Suan Lin, KKBOX Technologies.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
* Neither the name of the KKBOX Technologies nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
