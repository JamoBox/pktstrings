use cfg_if::cfg_if;
use colored::*;
use pcap::Packet;
use std::collections::HashMap;
use std::default::Default;
use std::fmt::Write;
use std::net::IpAddr;
use std::result::Result;

#[cfg(feature = "resolve")]
use dns_lookup::lookup_addr;

// IP next protos with port bytes all in same place :)
const TCP: u8 = 6;
const UDP: u8 = 17;
const DCCP: u8 = 33;
const SCTP: u8 = 132;

const IPV4: u16 = 0x0800;
const IPV6: u16 = 0x86dd;
const VLAN: u16 = 0x8100;

pub type Resolver = HashMap<IpAddr, String>;

fn get_field(data: &[u8], offset: usize, bitlen: usize) -> Result<u128, &str> {
    assert!(bitlen % 8 == 0, "Length must be positive multiple of 8");
    assert!(bitlen <= 128, "Length must be less than 128 bits");
    if (data.len() - offset) < bitlen / 8 {
        return Err("Data after offset is shorter than bitlen");
    }
    let mut addr: u128 = 0;
    for i in 0..(bitlen / 8) {
        addr |= (data[offset + i] as u128) << ((bitlen - 8) - (8 * i))
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
    pktsum.l2_dst = get_field(pkt, offset, 48).ok();
    pktsum.l2_src = get_field(pkt, offset + 6, 48).ok();

    let mut vlan_padding = 0;
    let ethertype = get_field(pkt.data, offset + 12, 16).map(|x| x as u16).ok();

    pktsum.ethertype = match ethertype {
        Some(VLAN) => {
            pktsum.vlan_id = get_field(pkt.data, offset + 14, 16).map(|x| x as u16).ok();
            vlan_padding = 4;

            get_field(pkt.data, offset + 16, 16).map(|x| x as u16).ok()
        }
        _ => ethertype,
    };

    Ok(offset + 14 + vlan_padding)
}

fn handle_ipv4(pkt: &Packet, offset: usize, pktsum: &mut PacketSummary) -> Result<usize, String> {
    let ihl: u8 = (pkt.data[offset] & 0xf) * 4;

    let next_offset: usize = offset + ihl as usize;

    pktsum.next_proto = Some(pkt.data[offset + 9]);
    pktsum.l3_src = get_field(pkt, offset + 12, 32).ok();
    pktsum.l3_dst = get_field(pkt, offset + 16, 32).ok();

    Ok(next_offset)
}

fn handle_ipv6(pkt: &Packet, offset: usize, pktsum: &mut PacketSummary) -> Result<usize, String> {
    pktsum.next_proto = Some(pkt.data[offset + 6]);
    pktsum.l3_src = get_field(pkt, offset + 8, 128).ok();
    pktsum.l3_dst = get_field(pkt, offset + 24, 128).ok();

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

#[derive(Eq, PartialEq, Default)]
pub struct PacketSummary<'a> {
    pub l2_src: Option<u128>,
    pub l2_dst: Option<u128>,
    pub ethertype: Option<u16>,
    pub vlan_id: Option<u16>,
    pub l3_src: Option<u128>,
    pub l3_dst: Option<u128>,
    pub next_proto: Option<u8>,
    pub l4_sport: Option<u16>,
    pub l4_dport: Option<u16>,
    pub resolver: Option<&'a mut HashMap<IpAddr, String>>,
}

impl<'a> PacketSummary<'a> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn from_packet(pkt: &Packet, resolver: Option<&'a mut HashMap<IpAddr, String>>) -> Self {
        let mut pktsum = Self::new();
        pktsum.resolver = resolver;

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
            Some(TCP) | Some(UDP) | Some(DCCP) | Some(SCTP) => {
                let sport_offset = l4_offset;
                let dport_offset = l4_offset + 2;
                pktsum.l4_sport = get_field(pkt.data, sport_offset, 16).ok().map(|x| x as u16);
                pktsum.l4_dport = get_field(pkt.data, dport_offset, 16).ok().map(|x| x as u16);
            }
            _ => {}
        }
        pktsum
    }

    pub fn formatted(&mut self) -> String {
        let mut out = String::from("[");

        let mut l3_src = String::new();
        let mut l3_dst = String::new();

        if let Some(vlan_id) = self.vlan_id {
            let tag = vlan_id.to_string();
            out.push_str(format!("Dot1Q: {} | ", tag.yellow()).as_str());
        }

        let l4_sport = match self.l4_sport {
            Some(p) => format!(":{}", p),
            None => String::new(),
        };

        let l4_dport = match self.l4_dport {
            Some(p) => format!(":{}", p),
            None => String::new(),
        };

        let next_proto = match self.next_proto {
            Some(1) => "ICMP".to_string(),
            Some(TCP) => "TCP".to_string(),
            Some(UDP) => "UDP".to_string(),
            Some(DCCP) => "DCCP".to_string(),
            Some(58) => "ICMPv6".to_string(),
            Some(SCTP) => "SCTP".to_string(),
            Some(proto) => proto.to_string(),
            _ => "-".to_string(),
        };

        let is_ip = match self.ethertype {
            Some(IPV6) => {
                int_to_ipv6_str(&self.l3_src.unwrap(), &mut l3_src);
                int_to_ipv6_str(&self.l3_dst.unwrap(), &mut l3_dst);
                true
            }
            Some(IPV4) => {
                int_to_ipv4_str(&(self.l3_src.unwrap() as u32), &mut l3_src);
                int_to_ipv4_str(&(self.l3_dst.unwrap() as u32), &mut l3_dst);
                true
            }
            _ => false,
        };

        if is_ip {
            cfg_if! {
                if #[cfg(feature = "resolve")] {
                    if let Some(resolver) = &mut self.resolver {
                        let srcip: IpAddr = l3_src.parse().unwrap();
                        let dstip: IpAddr = l3_dst.parse().unwrap();

                        let l3_src_resolved = resolver.entry(srcip).or_insert_with(|| {
                            match lookup_addr(&srcip) {
                                Ok(addr) => addr,
                                Err(_) => l3_src.to_string(),
                            }
                        });
                        out.push_str(
                            format!(
                                "{}{} → ",
                                l3_src_resolved.magenta(),
                                l4_sport.cyan(),
                            ).as_str()
                        );

                        let l3_dst_resolved = resolver.entry(dstip).or_insert_with(|| {
                            match lookup_addr(&dstip) {
                                Ok(addr) => addr,
                                Err(_) => l3_dst.to_string(),
                            }
                        });
                        out.push_str(
                            format!(
                                "{}{} ",
                                l3_dst_resolved.magenta(),
                                l4_dport.cyan(),
                            ).as_str()
                        );
                    } else {
                        out.push_str(
                            format!(
                                "{}{} → {}{} ",
                                l3_src.magenta(),
                                l4_sport.cyan(),
                                l3_dst.magenta(),
                                l4_dport.cyan(),
                            ).as_str()
                        );
                    }
                } else {
                    out.push_str(
                        format!(
                            "{}{} → {}{} ",
                            l3_src.magenta(),
                            l4_sport.cyan(),
                            l3_dst.magenta(),
                            l4_dport.cyan(),
                        ).as_str()
                    );
                }
            }
            out.push_str(format!("({})", next_proto.green()).as_str());
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

            out.push_str(
                format!(
                    "{} → {} ({})",
                    l2_src.magenta(),
                    l2_dst.magenta(),
                    ethertype.green(),
                )
                .as_str(),
            );
        }
        out.push(']');
        out
    }
}

#[cfg(test)]
mod tests {
    use libc::timeval;
    use pcap::{Packet, PacketHeader};

    use super::*;

    const REF_V4_PACKET: Packet = Packet {
        header: &PacketHeader {
            ts: timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: 77,
            len: 77,
        },
        data: &[
            0x0, 0x0, 0x0, 0x0, 0x0, 0x1, // dst
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // src
            0x81, 0x0, // 802.1q
            0x0f, 0xff, // VLAN ID 4095
            0x8, 0x0, // TPID IPv4
            0x45, 0x0, 0x0, 0x3b, 0x0, 0x1, // default headers
            0x0, 0x0, 0x40, 0x6, 0x3a, 0x12, // headers w/ TCP proto
            0x7f, 0x0, 0x0, 0x1, // src 127.0.0.1
            0xc0, 0xa8, 0x1, 0x1, // dst 192.168.1.1
            0x0, 0x50, // sport 80
            0x14, 0xeb, // dport 5355
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // headers
            0x50, 0x2, 0x20, 0x0, 0x76, 0x46, 0x0, 0x0, // headers
            0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
            0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
            0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
            0x74, 0x65, 0x73, 0x74, // test
        ],
    };

    const REF_V6_PACKET: Packet = Packet {
        header: &PacketHeader {
            ts: timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: 97,
            len: 97,
        },
        data: &[
            0x0, 0x0, 0x0, 0x0, 0x0, 0x1, // dst
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // src
            0x81, 0x0, // 802.1q
            0x0f, 0xff, // VLAN ID 4095
            0x86, 0xdd, // TPID IPv6
            0x60, 0x0, 0x0, 0x0, 0x0, 0x27, 0x6, 0x40, // default headers
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x1, // src ::1
            0x73, 0x57, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
            0x23, // dst 7357::123
            0x0, 0x50, // sport 80
            0x14, 0xeb, // dport 5355
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // headers
            0x50, 0x2, 0x20, 0x0, 0x42, 0x76, 0x0, 0x0, // headers
            0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
            0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
            0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
            0x74, 0x65, 0x73, 0x74, // test
        ],
    };

    #[test]
    fn test_get_field() {
        let data = &[0x01, 0x23, 0x34, 0x0f, 0xff, 0x56];
        let expected = 4095;

        let result = get_field(data, 3, 16);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn test_int_to_mac_str() {
        let expected = "00:00:00:00:00:01";

        let mut result = String::new();
        int_to_mac_str(&1u64, &mut result);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_int_to_ipv6_str() {
        let expected = "0000:0000:0000:0000:0000:0000:0000:0001";

        let mut result = String::new();
        int_to_ipv6_str(&1u128, &mut result);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_int_to_ipv4_str() {
        let expected = "0.0.0.1";

        let mut result = String::new();
        int_to_ipv4_str(&1u32, &mut result);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_from_packet_v4() {
        let pktsum = PacketSummary::from_packet(&REF_V4_PACKET, None);

        assert_eq!(pktsum.l2_dst.unwrap(), 1, "l2_dst");
        assert_eq!(pktsum.l2_src.unwrap(), 281474976710655, "l2_src");
        assert_eq!(pktsum.ethertype.unwrap(), 2048, "ethertype");
        assert_eq!(pktsum.vlan_id.unwrap(), 4095, "vlan_id");
        assert_eq!(pktsum.l3_src.unwrap(), 2130706433, "l3_src");
        assert_eq!(pktsum.l3_dst.unwrap(), 3232235777, "l3_dst");
        assert_eq!(pktsum.next_proto.unwrap(), 6, "next_proto");
        assert_eq!(pktsum.l4_sport.unwrap(), 80, "l4_sport");
        assert_eq!(pktsum.l4_dport.unwrap(), 5355, "l4_dport");
    }

    #[test]
    fn test_from_packet_v6() {
        let pktsum = PacketSummary::from_packet(&REF_V6_PACKET, None);

        assert_eq!(pktsum.l2_dst.unwrap(), 1, "l2_dst");
        assert_eq!(pktsum.l2_src.unwrap(), 281474976710655, "l2_src");
        assert_eq!(pktsum.ethertype.unwrap(), 34525, "ethertype");
        assert_eq!(pktsum.vlan_id.unwrap(), 4095, "vlan_id");
        assert_eq!(pktsum.l3_src.unwrap(), 1, "l3_src");
        assert_eq!(
            pktsum.l3_dst.unwrap(),
            153312949341957855387619965112881774883,
            "l3_dst"
        );
        assert_eq!(pktsum.next_proto.unwrap(), 6, "next_proto");
        assert_eq!(pktsum.l4_sport.unwrap(), 80, "l4_sport");
        assert_eq!(pktsum.l4_dport.unwrap(), 5355, "l4_dport");
    }

    #[test]
    fn test_handle_eth() {
        let mut pktsum = PacketSummary::new();
        let expected = 18;

        let result = handle_eth(&REF_V4_PACKET, 0, &mut pktsum);
        assert_eq!(result.unwrap(), expected, "offset");
        assert_eq!(pktsum.l2_dst.unwrap(), 1, "l2_dst");
        assert_eq!(pktsum.l2_src.unwrap(), 281474976710655, "l2_src");
        assert_eq!(pktsum.ethertype.unwrap(), 2048, "ethertype");
        assert_eq!(pktsum.vlan_id.unwrap(), 4095, "vlan_id");
    }

    #[test]
    fn test_handle_ipv4() {
        let mut pktsum = PacketSummary::new();
        let expected = 38;

        let result = handle_ipv4(&REF_V4_PACKET, 18, &mut pktsum);
        assert_eq!(result.unwrap(), expected, "offset");
        assert_eq!(pktsum.l3_src.unwrap(), 2130706433, "l3_src");
        assert_eq!(pktsum.l3_dst.unwrap(), 3232235777, "l3_dst");
        assert_eq!(pktsum.next_proto.unwrap(), 6, "next_proto");
    }

    #[test]
    fn test_handle_ipv6() {
        let mut pktsum = PacketSummary::new();
        let expected = 58;

        let result = handle_ipv6(&REF_V6_PACKET, 18, &mut pktsum);
        assert_eq!(result.unwrap(), expected, "offset");
        assert_eq!(pktsum.l3_src.unwrap(), 1, "l3_src");
        assert_eq!(
            pktsum.l3_dst.unwrap(),
            153312949341957855387619965112881774883,
            "l3_dst"
        );
        assert_eq!(pktsum.next_proto.unwrap(), 6, "next_proto");
    }

    #[test]
    fn test_handle_unknown() {
        let mut pktsum = PacketSummary::new();

        let result = handle_unknown(&REF_V4_PACKET, 0, &mut pktsum);
        assert!(result.is_err());
    }
}
