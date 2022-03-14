 [![pipeline status](https://gitlab.parker.systems/drew/rig-dns-tool/badges/main/pipeline.svg)](https://gitlab.parker.systems/drew/rig-dns-tool/-/commits/main) 

# Rig DNS Tool

Notice: this tool is very much a WIP.

A simple DNS lookup utility written in Rust.

## Intro
Every time I need to do something with dig I spend more time looking through the docs looking for exactly the right command than is reasonable.

This tool is an attempt to bring the more common usages of dig to the front, while not losing any of the other esoteric commands of dig.

## Usage
Current options are limited to something similar to a `dig +short`, but we're getting there.

```
❯ rig google.com
google.com.
142.250.9.101    197 IN A
142.250.9.100    197 IN A
142.250.9.102    197 IN A
142.250.9.113    197 IN A
142.250.9.138    197 IN A
142.250.9.139    197 IN A
```