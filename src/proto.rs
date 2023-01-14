pub trait ProtoResolver {
    fn resolve(&self) -> String;
}

/* Ethertypes */
pub type Ethertype = u16;

pub const IPV4: Ethertype = 0x0800;
pub const IPV6: Ethertype = 0x86dd;
pub const VLAN: Ethertype = 0x8100;

impl ProtoResolver for Ethertype {
    fn resolve(&self) -> String {
        match *self {
            IPV4 => "IPv4".to_string(),
            IPV6 => "IPv6".to_string(),
            VLAN => "VLAN".to_string(),
            _ => format!("0x{self:04x}"),
        }
    }
}

/* IP Next Proto/Header */
pub type NextProto = u8;

pub const HOPOPT: NextProto = 0;
pub const ICMP: NextProto = 1;
pub const TCP: NextProto = 6;
pub const UDP: NextProto = 17;
pub const DCCP: NextProto = 33;
pub const IPV6_ROUTE: NextProto = 43;
pub const IPV6_FRAG: NextProto = 44;
pub const AH: NextProto = 51;
pub const IPV6_ICMP: NextProto = 58;
pub const IPV6_NONXT: NextProto = 59;
pub const IPV6_OPTS: NextProto = 60;
pub const SCTP: NextProto = 132;

impl ProtoResolver for NextProto {
    fn resolve(&self) -> String {
        match *self {
            HOPOPT => "Hop-by-Hop".to_string(),
            ICMP => "ICMP".to_string(),
            TCP => "TCP".to_string(),
            UDP => "UDP".to_string(),
            DCCP => "DCCP".to_string(),
            IPV6_ROUTE => "Routing".to_string(),
            IPV6_FRAG => "Fragmented".to_string(),
            IPV6_ICMP => "ICMPv6".to_string(),
            IPV6_NONXT => "No Next Hdr".to_string(),
            IPV6_OPTS => "Dst Opts".to_string(),
            SCTP => "SCTP".to_string(),
            _ => self.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ethertype_resolve() {
        let expected = "IPv4";
        let ipv4: Ethertype = 0x0800;
        assert_eq!(ipv4.resolve(), expected);
    }

    #[test]
    fn test_next_proto_resolve() {
        let expected = "TCP";
        let tcp: NextProto = 6;
        assert_eq!(tcp.resolve(), expected);
    }
}
