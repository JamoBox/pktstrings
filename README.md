# pktstrings

![build status](https://github.com/JamoBox/pktstrings/actions/workflows/ci.yml/badge.svg)
![lint status](https://github.com/JamoBox/pktstrings/actions/workflows/rust-clippy.yml/badge.svg)
![crate license](https://img.shields.io/crates/l/pktstrings)
![crate version](https://img.shields.io/crates/v/pktstrings)

Ever ran `strings` on a PCAP and found something interesting, but left frustrated you have no context of which packet it occurred in?

Pktstrings is like Unix `strings` command, but packet-aware.

It finds anything looking like an ASCII string in your PCAP and dumps the packet number plus IP 5-tuple (or MACs + Ethertype if not IP) of where the strings were found.

![image](https://user-images.githubusercontent.com/2273100/201542679-2ce4e1c9-bb0e-40f5-899e-c75c55dbe860.png)

Requires libpcap headers (See [Dependencies](#Dependencies)) to build.

## Features
 - Support for both offline PCAPs and live network capture.
 - Filter which packets are analysed with BPF expressions.
 - Regex filtering on packets before attempting to find strings.
 - DNS resolver with local cache (`--feature resolve` to enable option).
 - Grep friendly (default) and copy friendly (`-b`, `--block-print`) output options.
 - Support for 802.1Q networks; showing the VLAN ID and IPs if present.

## Dependencies
Pktstrings uses the [pcap crate](https://crates.io/crates/pcap) and thus requires libpcap (or Npcap/WinPcap on Windows) to be installed before building.
Follow the instructions the pcap crate provides to get the correct installation instructions for your system.

https://github.com/rust-pcap/pcap#installing-dependencies

## Install
To install binary from crates.io
`cargo install pktstrings`

To install with optional DNS resolver flag (`-r, --resolve-dns`):
`cargo install pktstrings --features=resolve`

To install with colour output disabled:
`cargo install pktstrings --features=bland`

To install from cloned source:
`cargo install --path .`

## Running
Default install location is `~/.cargo/bin/pktstrings`.
Run pktstrings with `-h` for help and available options.

## About BPF & Regex
Pktstrings provides two ways to filter output noise when dumping strings; BPF expressions and regex.
BPF expressions should be preferred as they are by far the fastest way to cut down to packets of interest.
However, sometimes it's useful to be able to perform free-form searches rather than fixed place; so pktstrings also supports regular expressions as a way of further filtering down to only packets of interest. The regular expression based filtering passes the entire packet data through Rust's regex engine using the regex::bytes crate; this means as well as being able to match against string expressions we can also match against arbitrary bytes within the packet data. The expressions provided by the user have an implicit `.*?`.

The BPF and Regex filters act only as a pre-filter stage before performing the string search. Once a packet matches these filters, the data will undergo the standard ASCII string dump as usual.

## Examples
Only dump strings from packets that contain a certain string somewhere:
`pktstrings -f my_capture.pcap -s 'CTF_FLAG{.+}'`

Find mDNS chatter on local network:
`pktstrings -e 'udp port 5353'`

Basic auth logins to locally run HTTP server:
`pktstrings -i en0 -e 'tcp port 80' -s 'POST.+login.php'` 

HTTP response packets where a specific cookie is being set:
`pktstrings -f my_capture.pcap --resolve-dns -e 'ip src 192.168.1.100 and tcp port 80' -s 'Set-Cookie:.+\b[Dd]omain=.*some-http-server.com'`

Packets containing arbitrary byte pattern followed by a valid UTF-8 encoded string :
`pktstrings -f my_capture.pcap -s '(?-u)\x7b\xa9(?:[\x80-\xfe]|[\x40-\xff].)(?u:(.*))'`

## TODO (maybe):
- Other string encodings
- Support more protocols
- Full PCAPNG support
