# pktstrings

Ever ran `strings` on a PCAP and found something interesting, but left frustrated you have no context of which packet it occurred in?

Pktstrings is like Unix `strings` command, but packet-aware.

It finds anything looking like an ASCII string in your PCAP and dumps the packet number plus IP 5-tuple (or MACs + Ethertype if not IP) of where the strings were found.

![image](https://user-images.githubusercontent.com/2273100/201542679-2ce4e1c9-bb0e-40f5-899e-c75c55dbe860.png)

Requires libpcap headers (or Npcap on Windows) to build.

## Install
To install binary:
`cargo install --path .`

To install with optional DNS resolver flag (`-r, --resolve-dns`):
`cargo install --features=resolve --release`

To install with colour output disabled:
`cargo install --features=bland --release`

## Running
Default install location is `~/.cargo/bin/pktstrings`.
Run pktstrings with `-h` for help and available options.

## TODO:
- Optimisations
- Other encodings
- Better protocol support (e.g. IPv6 header parsing?)
