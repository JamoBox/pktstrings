use std::fmt;
use colored::*;
use pcap::Packet;
use std::result::Result;

#[cfg(feature = "resolve")]
use dns_lookup::lookup_addr;

#[cfg(feature = "resolve")]
use std::net::IpAddr;

const TCP: u8 = 6;
const UDP: u8 = 17;

const IPV4: u16 = 0x0800;
const IPV6: u16 = 0x86dd;

fn getaddr(data: &[u8], offset: usize, size: usize) -> Result<u128, &str> {
    if size <= 0 || size % 8 != 0 {
        println!("{size}");
        return Err("Size must be positive multiple of 8");
    }
    let mut addr: u128 = 0;
    for i in 0..(size / 8) {
        addr |= {
            (data[offset + i] as u128)
            << ((size - 8) - (8 * i))
        }
    }
    Ok(addr)
}

fn int_to_mac_str(addr: &u64, formatted: &mut String) {
    let bytes = addr.to_be_bytes();
    formatted.push_str(&format!("{:02x}", bytes[0]));
    for byte in bytes.iter() {
        formatted.push_str(&format!(":{:02x}", byte));
    }
}

fn int_to_ipv6_str(addr: &u128, formatted: &mut String) {
    let bytes = addr.to_be_bytes();
    formatted.push_str(&format!("{:02x}{:02x}", bytes[0], bytes[1]));
    for pair in bytes
        .iter()
        .skip(2)
        .step_by(2)
        .zip(bytes.iter().skip(3).step_by(2))
    {
        formatted.push_str(&format!(":{:02x}{:02x}", pair.0, pair.1));
    }
}

fn int_to_ipv4_str(addr: &u32, formatted: &mut String) {
    let bytes = addr.to_be_bytes();
    formatted.push_str(&format!("{}", bytes[0]));
    for byte in bytes.iter().skip(1) {
        formatted.push_str(&format!(".{}", byte));
    }
}

fn handle_eth(
    pkt: &Packet,
    offset: usize,
    pktsum: &mut PacketSummary,
) -> Result<usize, String> {
    pktsum.l2_dst = getaddr(pkt, offset, 48)?;
    pktsum.l2_src = getaddr(pkt, offset + 6, 48)?;
    pktsum.ethertype = {
        ((pkt.data[12] as u16) << 8) |
        (pkt.data[13] as u16)
    };

    Ok(14)
}

fn handle_ipv4(
    pkt: &Packet,
    offset: usize,
    pktsum: &mut PacketSummary,
) -> Result<usize, String> {
    let ihl: u8 = (pkt.data[offset] & 0xf) * 4;

    let next_offset: usize = offset + ihl as usize;

    pktsum.next_proto = pkt.data[offset + 9];
    pktsum.l3_src = getaddr(pkt, offset + 12, 32)?;
    pktsum.l3_dst = getaddr(pkt, offset + 16, 32)?;

    Ok(next_offset)
}

fn handle_ipv6(
    pkt: &Packet,
    offset: usize,
    pktsum: &mut PacketSummary,
) -> Result<usize, String> {
    pktsum.next_proto = pkt.data[offset + 6];
    pktsum.l3_src = getaddr(pkt, offset + 8, 128)?;
    pktsum.l3_dst = getaddr(pkt, offset + 24, 128)?;

    // TODO: parse headers
    Ok(offset + 40)
}

fn handle_unknown(
    _pkt: &Packet,
    _offset: usize,
    _pktsum: &mut PacketSummary,
) -> Result<usize, String> {
    Ok(0)
}

#[derive(Eq, PartialEq, Hash)]
pub struct PacketSummary {
    pub l2_src: u128,
    pub l2_dst: u128,
    pub ethertype: u16,
    pub l3_src: u128,
    pub l3_dst: u128,
    pub next_proto: u8,
    pub l4_sport: u16,
    pub l4_dport: u16,
    pub resolve: bool,
}

impl PacketSummary {
    pub fn new() -> Self {
        Self {
            ethertype: 0,
            l2_src: 0,
            l2_dst: 0,
            l3_src: 0,
            l3_dst: 0,
            next_proto: 0,
            l4_sport: 0,
            l4_dport: 0,
            resolve: false,
        }
    }

    pub fn from_packet(pkt: &Packet, resolve_dns: bool) -> Self {
        let mut pktsum = Self::new();

        pktsum.resolve = resolve_dns;

        let l3_offset = match handle_eth(&pkt, 0, &mut pktsum) {
            Ok(o) => o,
            Err(_) => return pktsum,  // cannot continue
        };
        let l3_callback = match pktsum.ethertype {
            IPV4 => handle_ipv4,
            IPV6 => handle_ipv6,
            _ => handle_unknown,
        };
        let l4_offset = match l3_callback(&pkt, l3_offset, &mut pktsum) {
            Ok(o) => o,
            Err(_) => return pktsum,  // cannot continue
        };

        match pktsum.next_proto {
            TCP | UDP => {
                pktsum.l4_sport = ((pkt.data[l4_offset] as u16) << 8)
                    | pkt.data[l4_offset + 1] as u16;
                pktsum.l4_dport = ((pkt.data[l4_offset + 2] as u16) << 8)
                    | pkt.data[l4_offset + 3] as u16;
            }
            _ => {}
        }
        pktsum
    }
}

impl fmt::Display for PacketSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut l3_src = String::new();
        let mut l3_dst = String::new();
        let l4_sport = match self.l4_sport {
            0 => String::new(),
            non_zero => format!(":{}", non_zero.to_string()),
        };
        let l4_dport = match self.l4_dport {
            0 => String::new(),
            non_zero => format!(":{}", non_zero.to_string()),
        };
        let next_proto = self.next_proto.to_string();

        let is_ip;
        match self.ethertype {
            IPV6 => {
                int_to_ipv6_str(&self.l3_src, &mut l3_src);
                int_to_ipv6_str(&self.l3_dst, &mut l3_dst);
                is_ip = true;
            },
            IPV4 => {
                int_to_ipv4_str(&(self.l3_src as u32), &mut l3_src);
                int_to_ipv4_str(&(self.l3_dst as u32), &mut l3_dst);
                is_ip = true;
            },
            _ => is_ip = false,
        }

        if is_ip {

            #[cfg(feature = "resolve")]
            if self.resolve {
                let srcip: IpAddr = l3_src.parse().unwrap();
                let dstip: IpAddr = l3_dst.parse().unwrap();

                match lookup_addr(&srcip) {
                    Ok(r) => l3_src = r,
                    Err(_) => {},
                }

                match lookup_addr(&dstip) {
                    Ok(r) => l3_src = r,
                    Err(_) => {},
                }
            }

            write!(
                f,
                "[{}{} → {}{} ({})]",
                l3_src.magenta(),
                l4_sport.cyan(),
                l3_dst.magenta(),
                l4_dport.cyan(),
                next_proto.green(),
            )
        } else {
            let mut l2_src = String::new();
            let mut l2_dst = String::new();
            let ethertype = self.ethertype.to_string();

            int_to_mac_str(&(self.l2_src as u64), &mut l2_src);
            int_to_mac_str(&(self.l2_dst as u64), &mut l2_dst);

            write!(
                f,
                "[{} → {} ({})]",
                l2_src.magenta(),
                l2_dst.magenta(),
                ethertype.green(),
            )
        }
    }
}
