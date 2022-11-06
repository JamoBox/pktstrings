use colored::*;
use pcap::Packet;
use std::fmt;
use std::fmt::Write;
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
    if size % 8 != 0 {
        println!("{size}");
        return Err("Size must be positive multiple of 8");
    }
    let mut addr: u128 = 0;
    for i in 0..(size / 8) {
        addr |= (data[offset + i] as u128) << ((size - 8) - (8 * i)) 
    }
    Ok(addr)
}

fn int_to_mac_str(addr: &u64, formatted: &mut String) {
    let bytes = addr.to_be_bytes();
    write!(formatted, "{:02x}", bytes[2]).unwrap();
    for byte in bytes[3..].iter() {
        write!(formatted, ":{:02x}", byte).unwrap();
    }
}

fn int_to_ipv6_str(addr: &u128, formatted: &mut String) {
    let bytes = addr.to_be_bytes();
    write!(formatted, "{:02x}{:02x}", bytes[0], bytes[1]).unwrap();
    for pair in bytes
        .iter()
        .skip(2)
        .step_by(2)
        .zip(bytes.iter().skip(3).step_by(2))
    {
        write!(formatted, ":{:02x}{:02x}", pair.0, pair.1).unwrap();
    }
}

fn int_to_ipv4_str(addr: &u32, formatted: &mut String) {
    let bytes = addr.to_be_bytes();
    write!(formatted, "{}", bytes[0]).unwrap();
    for byte in bytes.iter().skip(1) {
        write!(formatted, ".{}", byte).unwrap();
    }
}

fn handle_eth(pkt: &Packet, offset: usize, pktsum: &mut PacketSummary) -> Result<usize, String> {
    pktsum.l2_dst = getaddr(pkt, offset, 48).ok();
    pktsum.l2_src = getaddr(pkt, offset + 6, 48).ok();
    pktsum.ethertype = Some(((pkt.data[12] as u16) << 8) | (pkt.data[13] as u16));

    Ok(14)
}

fn handle_ipv4(pkt: &Packet, offset: usize, pktsum: &mut PacketSummary) -> Result<usize, String> {
    let ihl: u8 = (pkt.data[offset] & 0xf) * 4;

    let next_offset: usize = offset + ihl as usize;

    pktsum.next_proto = Some(pkt.data[offset + 9]);
    pktsum.l3_src = getaddr(pkt, offset + 12, 32).ok();
    pktsum.l3_dst = getaddr(pkt, offset + 16, 32).ok();

    Ok(next_offset)
}

fn handle_ipv6(pkt: &Packet, offset: usize, pktsum: &mut PacketSummary) -> Result<usize, String> {
    pktsum.next_proto = Some(pkt.data[offset + 6]);
    pktsum.l3_src = getaddr(pkt, offset + 8, 128).ok();
    pktsum.l3_dst = getaddr(pkt, offset + 24, 128).ok();

    // TODO: parse headers
    Ok(offset + 40)
}

fn handle_unknown(
    _pkt: &Packet,
    _offset: usize,
    _pktsum: &mut PacketSummary,
) -> Result<usize, String> {
    Err("Unknown protocol".to_string())
}

#[derive(Eq, PartialEq, Hash)]
pub struct PacketSummary {
    pub l2_src: Option<u128>,
    pub l2_dst: Option<u128>,
    pub ethertype: Option<u16>,
    pub l3_src: Option<u128>,
    pub l3_dst: Option<u128>,
    pub next_proto: Option<u8>,
    pub l4_sport: Option<u16>,
    pub l4_dport: Option<u16>,
    pub resolve: bool,
}

impl PacketSummary {
    pub fn new() -> Self {
        Self {
            ethertype: None,
            l2_src: None,
            l2_dst: None,
            l3_src: None,
            l3_dst: None,
            next_proto: None,
            l4_sport: None,
            l4_dport: None,
            resolve: false,
        }
    }

    pub fn from_packet(pkt: &Packet, resolve_dns: bool) -> Self {
        let mut pktsum = Self::new();

        pktsum.resolve = resolve_dns;

        let l3_offset = match handle_eth(pkt, 0, &mut pktsum) {
            Ok(o) => o,
            Err(_) => return pktsum, // cannot continue
        };
        let l3_callback = match pktsum.ethertype {
            Some(IPV4) => handle_ipv4,
            Some(IPV6) => handle_ipv6,
            _ => handle_unknown,
        };
        let l4_offset = match l3_callback(pkt, l3_offset, &mut pktsum) {
            Ok(o) => o,
            Err(_) => return pktsum, // cannot continue
        };

        match pktsum.next_proto {
            Some(TCP) | Some(UDP) => {
                pktsum.l4_sport =
                    Some(((pkt.data[l4_offset] as u16) << 8) | pkt.data[l4_offset + 1] as u16);
                pktsum.l4_dport =
                    Some(((pkt.data[l4_offset + 2] as u16) << 8) | pkt.data[l4_offset + 3] as u16);
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
            Some(non_zero) => format!(":{}", non_zero),
            None => String::new(),
        };

        let l4_dport = match self.l4_dport {
            Some(non_zero) => format!(":{}", non_zero),
            None => String::new(),
        };

        let next_proto = if let Some(np) = self.next_proto {
            np.to_string()
        } else {
            "-".to_string()
        };

        let is_ip = match self.ethertype {
            // defaulting IPs to 0 is weird, but having an ethertype set as IP
            // and not actually having an IP value is probably weirder?
            Some(IPV6) => {
                int_to_ipv6_str(&self.l3_src.unwrap_or(0), &mut l3_src);
                int_to_ipv6_str(&self.l3_dst.unwrap_or(0), &mut l3_dst);
                true
            },
            Some(IPV4) => {
                int_to_ipv4_str(&(self.l3_src.unwrap_or(0) as u32), &mut l3_src);
                int_to_ipv4_str(&(self.l3_dst.unwrap_or(0) as u32), &mut l3_dst);
                true
            },
            _ => false,
        };

        if is_ip {
            #[cfg(feature = "resolve")]
            if self.resolve {
                let srcip: IpAddr = l3_src.parse().unwrap();
                let dstip: IpAddr = l3_dst.parse().unwrap();

                match lookup_addr(&srcip) {
                    Ok(r) => l3_src = r,
                    Err(_) => {}
                }

                match lookup_addr(&dstip) {
                    Ok(r) => l3_src = r,
                    Err(_) => {}
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
            let mut ethertype = String::new();

            int_to_mac_str(&(self.l2_src.unwrap_or(0) as u64), &mut l2_src);
            int_to_mac_str(&(self.l2_dst.unwrap_or(0) as u64), &mut l2_dst);

            let _ = match self.ethertype {
                Some(et) => write!(ethertype, "{:04x}", et).ok(),
                _ => write!(ethertype, "----").ok(),
            };


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
