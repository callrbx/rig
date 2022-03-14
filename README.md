 [![pipeline status](https://gitlab.parker.systems/drew/rig-dns-tool/badges/main/pipeline.svg)](https://gitlab.parker.systems/drew/rig-dns-tool/-/commits/main) 

# Rig DNS Tool

Notice: this tool is very much a WIP.

A simple DNS lookup utility written in Rust.

## Intro
Every time I need to do something with dig I spend more time looking through the docs looking for exactly the right command than is reasonable.

This tool is an attempt to bring the more common usages of dig to the front, while not losing any of the other esoteric commands of dig.

## Usage
Current useage is limited to piping output into a tool like netcat

```
❯ target/release/rig github.com | nc -u 1.1.1.1 53 | xxd
00000000: 3749 8180 0001 0001 0000 0000 0667 6974  7I...........git
00000010: 6875 6203 636f 6d00 0001 0001 c00c 0001  hub.com.........
```