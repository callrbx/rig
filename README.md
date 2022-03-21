 [![CICD](https://gitlab.parker.systems/drew/rig-dns-tool/badges/main/pipeline.svg)](https://gitlab.parker.systems/drew/rig-dns-tool/-/commits/main) 

# Rig DNS Tool

Notice: this tool is very much a WIP.

A simple DNS lookup utility written in Rust.

## Intro
Every time I need to do something with dig I spend more time looking through the docs looking for exactly the right command than is reasonable.

This tool is an attempt to bring the more common usages of dig to the front, while not losing any of the other esoteric commands of dig.

## Usage Examples


Basic Usage:
```
❯ rig google.com
google.com.
64.233.177.113   256 IN A
64.233.177.139   256 IN A
64.233.177.101   256 IN A
64.233.177.138   256 IN A
64.233.177.100   256 IN A
64.233.177.102   256 IN A
```

Multiple Hostnames:
```
❯ rig google.com dns.google.com
google.com.
64.233.177.139   166 IN A
64.233.177.101   166 IN A
64.233.177.138   166 IN A
64.233.177.100   166 IN A
64.233.177.102   166 IN A
64.233.177.113   166 IN A

dns.google.com.
8.8.4.4          793 IN A
8.8.8.8          793 IN A
```

Specific Nameserver:
```
❯ rig -s 1.1.1.1 google.com
google.com.
172.217.10.110   249 IN A
```

Help Usage:
```
❯ rig -h
rig 0.1.0
Drew Parker
Fully featured DNS lookup utility, utilizing librig

USAGE:
    rig [OPTIONS] [hostnames]...

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -s, --server <server>    server to perform lookups against <IP:port> (53 assumed if not set)

ARGS:
    <hostnames>...
```