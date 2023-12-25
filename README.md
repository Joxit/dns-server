# DNS Server

[![Pulls](https://img.shields.io/docker/pulls/joxit/dns-server.svg?maxAge=86400)](https://hub.docker.com/r/joxit/dns-server)
[![Langs](https://img.shields.io/github/languages/top/joxit/dns-server)](https://github.com/Joxit/dns-server)
[![Project](https://img.shields.io/badge/joxit-dns_server-blue?logo=github)](https://github.com/Joxit/dns-server)
[![website](https://img.shields.io/badge/website-dns_server-blue)](https://joxit.dev/dns-server)
[![Sponsor](https://joxit.dev/images/sponsor.svg)](https://github.com/sponsors/Joxit)

## Overview

This project aims to provide a simple dns server you can deploy and to blacklist domains (ads, malware...). Provide your own list of all domains to block and use your favorite DNS Resolver for authorised domains (only cloudflare and google over UDP/TLS/HTTPS are available).

The Server can listen for queries on UDP (port 53), TLS/TCP (port 853) and HTTPS/H2 (port 443).
The Resolver can send queries on UDP (port 53), TLS/TCP (port 853) or HTTPS/H2 (port 443).

Project built using rust and available on [Docker Hub](https://hub.docker.com/r/joxit/dns-server).

## Usage

```
Create a DNS server you can configure to block some domain and zones. You can use UDP or DNS over TLS/TCP (DoT) or DNS over HTTPS/H2 (DoH) as listeners (frontend) and resolver (backend)

Usage: dns-server [OPTIONS]

Options:
  -p, --port <PORT>
          Listen port of the classic DNS server over UDP [default: 53]
  -l, --listen <LISTEN>
          Listen adress of the server [default: 0.0.0.0]
      --workers <WORKER>
          Number of workers to setup [default: 4]
      --blacklist <BLACKLIST>
          File containing a list of exact domains to block
      --default-ip <DEFAULT_IP>
          Default IP address to return when the domain is blocked instead of an empty NoError response
      --zone-blacklist <ZONE_BLACKLIST>
          File containing a list of zone of domains to block, this will block the domain and all subdomains
      --dns-server <DNS_SERVER>
          Setup your trusted dns resolver, could be cloudflare or google with UDP, TLS or H2. The port is optional when you are using custom IP. When you use TLS or H2 protocols, you must add the domain name too [default: cloudflare:h2] [possible values: cloudflare, google, cloudflare:tls, google:tls, cloudflare:h2, google:h2, ipv4:port, [ipv6]:port, ipv4:port:<tls|h2>:domain, [ipv6]:port:<tls|h2>:domain]
      --h2
          Activate https/h2 server beside classic DNS server over UDP
      --h2-port <H2_PORT>
          Listen port of the https/h2 server [default: 443]
      --tls
          Activate DNS over TLS (TCP) server beside classic DNS server over UDP
      --tls-port <TLS_PORT>
          Listen port of the Dns over TLS (TCP) server [default: 853]
      --tls-certificate <TLS_CERTIFICATE>
          Path of the certificate for the https/h2 server
      --tls-private-key <TLS_PRIVATE_KEY>
          Path of the private key for the https/h2 server
  -h, --help
          Print help
  -V, --version
          Print version
```

## Blacklist domain names

You have two ways to block domain names, both are based on files, one domain per line. All domains in the file given to `--blacklist` will be blocked only if they exactly match the query. By using `--zone-blacklist` you will block the domain and all its subdomains.

You have the choice between returning a specific IP with `--default-ip` for your blocked domain or send an empty response.

## DNS Server resolver

You can add another DNS resolver (different than Cloudflare and Google) with the `--dns-server` option. The format is `ip:port:protocol:domain`. Some examples with ipv4 and ipv6 and cloudflare IPs.

```
# UDP DNS IPv4
--dns-server 1.1.1.1 # cloudflare UDP DNS IPv4 with default port
--dns-server 1.1.1.1:53 # cloudflare UDP DNS IPv4

# UDP DNS IPv6
--dns-server [2606:4700:4700::1111] # cloudflare UDP DNS IPv6 with default port
--dns-server [2606:4700:4700::1111]:53 # cloudflare UDP DNS IPv6

# TLS DNS IPv4
--dns-server 1.1.1.1:tls:cloudflare-dns.com # cloudflare TLS DNS IPv4 with default port
--dns-server 1.1.1.1:853:tls:cloudflare-dns.com # cloudflare TLS DNS IPv4

# TLS DNS IPv6
--dns-server [2606:4700:4700::1111]:tls:cloudflare-dns.com # cloudflare TLS DNS IPv6 with default port
--dns-server [2606:4700:4700::1111]:853:tls:cloudflare-dns.com # cloudflare TLS DNS IPv6

# H2 DNS IPv4
--dns-server 1.1.1.1:h2:cloudflare-dns.com # cloudflare H2 DNS IPv4 with default port
--dns-server 1.1.1.1:443:h2:cloudflare-dns.com # cloudflare H2 DNS IPv4

# H2 DNS IPv6
--dns-server [2606:4700:4700::1111]:h2:cloudflare-dns.com # cloudflare H2 DNS IPv6 with default port
--dns-server [2606:4700:4700::1111]:443:h2:cloudflare-dns.com # cloudflare H2 DNS IPv6
```
