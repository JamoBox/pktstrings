# pktstrings

![build status](https://github.com/JamoBox/pktstrings/actions/workflows/ci.yml/badge.svg)
![lint status](https://github.com/JamoBox/pktstrings/actions/workflows/rust-clippy.yml/badge.svg)

Ever ran `strings` on a PCAP and found something interesting, but left frustrated you have no context of which packet it occurred in?

Pktstrings is like Unix `strings` command, but packet-aware.

It finds anything looking like an ASCII string in your PCAP and dumps the packet number plus IP 5-tuple (or MACs + Ethertype if not IP) of where the strings were found.

![image](https://user-images.githubusercontent.com/2273100/201542679-2ce4e1c9-bb0e-40f5-899e-c75c55dbe860.png)

Requires libpcap headers (See [Dependencies](#Dependencies)) to build.

## Features
 - Support for both offline PCAPs and live network capture
 - Filter which packets are analysed with BPF expressions
 - DNS resolver with local cache (`--feature resolve` to enable option)
 - Grep friendly (default) and copy friendly (`-b`, `--block-print`) output options
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

## TODO:
- More optimisations
- Possibly PCAPNG
- Other encodings
- Better protocol support (e.g. IPv6 header parsing?)
