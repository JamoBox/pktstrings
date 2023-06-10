use cfg_if::cfg_if;
use colored::*;
use pcap::Packet;
use std::collections::HashMap;
use std::default::Default;
use std::fmt::Write;
use std::net::IpAddr;
use std::result::Result;

use crate::proto::*;

#[cfg(feature = "resolve")]
use dns_lookup::lookup_addr;

pub type Resolver = HashMap<IpAddr, String>;

#[derive(Eq, PartialEq, Default)]
pub struct PacketSummary<'a> {
    pub l2_src: Option<u128>,
    pub l2_dst: Option<u128>,
    pub ethertype: Option<Ethertype>,
    pub vlan_id: Option<u16>,
    pub l3_src: Option<u128>,
    pub l3_dst: Option<u128>,
    pub next_proto: Option<NextProto>,
    pub l4_sport: Option<u16>,
    pub l4_dport: Option<u16>,
    pub resolver: Option<&'a mut HashMap<IpAddr, String>>,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Eq, PartialEq, Debug)]
pub enum ProtoHandler {
    COMPLETE, // special member
    UNKNOWN,  // special member
    ETH,
    VLAN,
    IPV4,
    IPV6,
    UDP,
    TCP,
    DCCP,
    SCTP,
}

pub fn handle_protocol(
    pkt: &Packet,
    offset: usize,
    pktsum: &mut PacketSummary,
    proto: &ProtoHandler,
) -> Result<(usize, ProtoHandler), String> {
    let handler = match proto {
        ProtoHandler::ETH => handle_eth,
        ProtoHandler::VLAN => handle_vlan,
        ProtoHandler::IPV4 => handle_ipv4,
        ProtoHandler::IPV6 => handle_ipv6,
        ProtoHandler::UDP => handle_ports,
        ProtoHandler::TCP => handle_ports,
        ProtoHandler::SCTP => handle_ports,
        ProtoHandler::DCCP => handle_ports,
        _ => handle_unknown,
    };

    handler(pkt, offset, pktsum)
}

pub fn get_field(data: &[u8], offset: usize, bitlen: usize) -> Result<u128, &str> {
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

pub fn int_to_mac_str(addr: &u64, formatted: &mut String) {
    let bytes = addr.to_be_bytes();
    write!(formatted, "{:02x}", bytes[2]).unwrap();
    for byte in bytes[3..].iter() {
        write!(formatted, ":{:02x}", byte).unwrap();
    }
}

pub fn int_to_ipv6_str(addr: &u128, formatted: &mut String) {
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

pub fn int_to_ipv4_str(addr: &u32, formatted: &mut String) {
    let bytes = addr.to_be_bytes();
    write!(formatted, "{}", bytes[0]).unwrap();
    for byte in bytes.iter().skip(1) {
        write!(formatted, ".{}", byte).unwrap();
    }
}

pub fn get_ethertype_handler(ethertype: &Option<Ethertype>) -> ProtoHandler {
    match ethertype {
        Some(VLAN) => ProtoHandler::VLAN,
        Some(IPV4) => ProtoHandler::IPV4,
        Some(IPV6) => ProtoHandler::IPV6,
        _ => ProtoHandler::UNKNOWN,
    }
}

pub fn get_nextproto_handler(next_proto: &Option<NextProto>) -> ProtoHandler {
    match next_proto {
        Some(TCP) => ProtoHandler::TCP,
        Some(UDP) => ProtoHandler::UDP,
        Some(DCCP) => ProtoHandler::DCCP,
        Some(SCTP) => ProtoHandler::SCTP,
        _ => ProtoHandler::UNKNOWN,
    }
}

pub fn handle_eth(
    pkt: &Packet,
    offset: usize,
    pktsum: &mut PacketSummary,
) -> Result<(usize, ProtoHandler), String> {
    pktsum.l2_dst = get_field(pkt, offset, 48).ok();
    pktsum.l2_src = get_field(pkt, offset + 6, 48).ok();
    pktsum.ethertype = get_field(pkt.data, offset + 12, 16).map(|x| x as u16).ok();

    let next_proto_hdl = get_ethertype_handler(&pktsum.ethertype);

    Ok((offset + 14, next_proto_hdl))
}

pub fn handle_vlan(
    pkt: &Packet,
    offset: usize,
    pktsum: &mut PacketSummary,
) -> Result<(usize, ProtoHandler), String> {
    pktsum.vlan_id = get_field(pkt.data, offset, 16)
        .map(|x| x as u16 & 0xfff)
        .ok();
    pktsum.ethertype = get_field(pkt.data, offset + 2, 16).map(|x| x as u16).ok();

    let next_proto_hdl = get_ethertype_handler(&pktsum.ethertype);

    Ok((offset + 4, next_proto_hdl))
}

pub fn handle_ipv4(
    pkt: &Packet,
    offset: usize,
    pktsum: &mut PacketSummary,
) -> Result<(usize, ProtoHandler), String> {
    let ihl = ((pkt.data[offset] & 0xf) * 4) as usize;

    pktsum.next_proto = Some(pkt.data[offset + 9]);
    pktsum.l3_src = get_field(pkt, offset + 12, 32).ok();
    pktsum.l3_dst = get_field(pkt, offset + 16, 32).ok();

    let next_proto_hdl = get_nextproto_handler(&pktsum.next_proto);

    Ok((offset + ihl, next_proto_hdl))
}

pub fn handle_ipv6(
    pkt: &Packet,
    offset: usize,
    pktsum: &mut PacketSummary,
) -> Result<(usize, ProtoHandler), String> {
    let mut next_offset = offset + 40;
    let mut next_proto = pkt.data[offset + 6];

    pktsum.l3_src = get_field(pkt, offset + 8, 128).ok();
    pktsum.l3_dst = get_field(pkt, offset + 24, 128).ok();

    // walk until we hit bottom of IPv6 header stack
    let mut bos = false;
    while !bos {
        match next_proto {
            HOPOPT | IPV6_ROUTE | IPV6_OPTS => {
                next_proto = pkt[next_offset];
                next_offset += 8 + (pkt[next_offset + 1] * 8) as usize;
            }
            IPV6_FRAG => {
                let frag = get_field(pkt, next_offset + 2, 16)
                    .map(|x| x as u16 & 0xff8)
                    .unwrap();
                next_proto = pkt[next_offset];
                next_offset += 8;

                // if we aren't on the first fragment then pass an error up
                // to prevent the protocol walker from continuing to try and parse
                // whatever data that follows as an L4 header.
                if frag != 0 {
                    // IPv6 Frag, halt parsing
                    pktsum.next_proto = Some(next_proto);
                    return Ok((next_offset, ProtoHandler::COMPLETE));
                }
                bos = true; // prevent re-looping as we will always be BoS here
            }
            AH => {
                // IPv6 Auth Hdr, halt parsing
                pktsum.next_proto = Some(next_proto);
                return Ok((next_offset, ProtoHandler::COMPLETE));
            }
            IPV6_NONXT => {
                // IPv6 No Next Header, halt parsing
                pktsum.next_proto = Some(next_proto);
                return Ok((next_offset, ProtoHandler::COMPLETE));
            }
            _ => bos = true,
        };
    }

    pktsum.next_proto = Some(next_proto);

    let next_proto_hdl = get_nextproto_handler(&pktsum.next_proto);

    Ok((next_offset, next_proto_hdl))
}

pub fn handle_ports(
    pkt: &Packet,
    offset: usize,
    pktsum: &mut PacketSummary,
) -> Result<(usize, ProtoHandler), String> {
    let sport_offset = offset;
    let dport_offset = offset + 2;
    pktsum.l4_sport = get_field(pkt.data, sport_offset, 16).ok().map(|x| x as u16);
    pktsum.l4_dport = get_field(pkt.data, dport_offset, 16).ok().map(|x| x as u16);

    Ok((offset + 4, ProtoHandler::COMPLETE))
}

pub fn handle_unknown(
    _pkt: &Packet,
    _offset: usize,
    _pktsum: &mut PacketSummary,
) -> Result<(usize, ProtoHandler), String> {
    Err("Unknown protocol".to_string())
}

impl<'a> PacketSummary<'a> {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn from_packet(pkt: &Packet, resolver: Option<&'a mut HashMap<IpAddr, String>>) -> Self {
        let mut pktsum = Self::new();
        pktsum.resolver = resolver;

        // start with Ethernet handler at offset 0
        let mut offset = 0;
        let mut proto_handler = ProtoHandler::ETH;

        // walk the protocol stacks until we hit something we cannot handle.
        // the handlers will populate pktsum as we go.
        loop {
            break match proto_handler {
                ProtoHandler::UNKNOWN => {}  // walking complete
                ProtoHandler::COMPLETE => {} // walking complete
                _ => {
                    match handle_protocol(pkt, offset, &mut pktsum, &proto_handler) {
                        Ok((o, h)) => {
                            // move offset & handler onto returned values
                            offset = o;
                            proto_handler = h;
                        }
                        Err(_) => return pktsum, // cannot continue
                    }
                    continue; // don't break, continue walking
                }
            };
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

        let mut next_proto = "-".to_string();
        if let Some(np) = self.next_proto {
            next_proto = np.resolve();
        }

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
            // create with 17 byte capacity as this will be fixed len
            let mut l2_src = String::with_capacity(17);
            let mut l2_dst = String::with_capacity(17);

            int_to_mac_str(&(self.l2_src.unwrap_or(0) as u64), &mut l2_src);
            int_to_mac_str(&(self.l2_dst.unwrap_or(0) as u64), &mut l2_dst);

            let mut ethertype = "----".to_string();
            if let Some(et) = self.ethertype {
                ethertype = et.resolve();
            }

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
            0x5f, 0xff, // VLAN ID 4095
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
            /* Ethernet + Dot1Q */
            0x0, 0x0, 0x0, 0x0, 0x0, 0x1, // dst
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // src
            0x81, 0x0, // 802.1q
            0x5f, 0xff, // VLAN ID 4095
            0x86, 0xdd, // TPID IPv6
            /* IPv6 */
            0x60, 0x0, 0x0, 0x0, 0x0, 0x27, 0x0, 0x40, // defaults + Hop-By-Hop Next Header
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x1, // src ::1
            0x73, 0x57, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
            0x23, // dst 7357::123
            /* Hop-By-Hop */
            0x3c, // Next Header
            0x01, // Hdr Ext Len
            b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
            /* Destination Options */
            0x2b, // Next Header
            0x01, // Hdr Ext Len
            b'B', b'B', b'B', b'B', b'B', b'B', b'B', b'B', b'B', b'B', b'B', b'B', b'B', b'B',
            /* Routing */
            0x2c, // Next Header
            0x01, // Hdr Ext Len
            0x04, // Routing Type
            0x02, // Segments Left
            b'C', b'C', b'C', b'C', b'C', b'C', b'C', b'C', b'C', b'C', b'C', b'C',
            /* Fragment */
            0x6,  // Next Header
            0x00, // Reserved
            0x00, 0x00, // Fragment Offset
            0x00, 0x00, 0x04, 0xd2, // Identification
            /* TCP */
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
        let expected = (14, ProtoHandler::VLAN);

        let result = handle_eth(&REF_V4_PACKET, 0, &mut pktsum);
        assert_eq!(result.unwrap(), expected, "offset");
        assert_eq!(pktsum.l2_dst.unwrap(), 1, "l2_dst");
        assert_eq!(pktsum.l2_src.unwrap(), 281474976710655, "l2_src");
    }

    #[test]
    fn test_handle_vlan() {
        let mut pktsum = PacketSummary::new();
        let expected = (18, ProtoHandler::IPV4);

        let result = handle_vlan(&REF_V4_PACKET, 14, &mut pktsum);
        assert_eq!(result.unwrap(), expected, "offset");
        assert_eq!(pktsum.ethertype.unwrap(), 2048, "ethertype");
        assert_eq!(pktsum.vlan_id.unwrap(), 4095, "vlan_id");
    }

    #[test]
    fn test_handle_ipv4() {
        let mut pktsum = PacketSummary::new();
        let expected = (38, ProtoHandler::TCP);

        let result = handle_ipv4(&REF_V4_PACKET, 18, &mut pktsum);
        assert_eq!(result.unwrap(), expected, "offset");
        assert_eq!(pktsum.l3_src.unwrap(), 2130706433, "l3_src");
        assert_eq!(pktsum.l3_dst.unwrap(), 3232235777, "l3_dst");
        assert_eq!(pktsum.next_proto.unwrap(), 6, "next_proto");
    }

    #[test]
    fn test_handle_ipv6() {
        let mut pktsum = PacketSummary::new();
        let expected = (114, ProtoHandler::TCP);

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
