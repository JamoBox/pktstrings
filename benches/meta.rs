#![allow(dead_code)]

use libc::timeval;
use pcap::{Packet, PacketHeader};

pub(crate) const REF_V4_PACKET: Packet = Packet {
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

pub(crate) const REF_V6_PACKET: Packet = Packet {
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

pub(crate) const DATA: &[u8] = &[
    /* Ethernet + Dot1Q */
    0x0, 0x0, 0x0, 0x0, 0x0, 0x1, // dst
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // src
    0x81, 0x0, // 802.1q
    0x5f, 0xff, // VLAN ID 4095
    0x86, 0xdd, // TPID IPv6
    /* IPv6 */
    0x60, 0x0, 0x0, 0x0, 0x0, 0x27, 0x0, 0x40, // defaults + Hop-By-Hop Next Header
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, // src ::1
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
    0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
    0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
    0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
    0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
    0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
    0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
    0x74, 0x65, 0x73, 0x74, 0x20, // test<space>
    0x74, 0x65, 0x73, 0x74, // test
];