use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use pktstrings::net::get_field;

const DATA: &[u8] = &[
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

fn from_elem(c: &mut Criterion) {
    
    let mut group = c.benchmark_group("Int field from byte slice");
    for bytelen in 0..16 {
        group.throughput(Throughput::Bytes(bytelen as u64));
        group.bench_with_input(BenchmarkId::new("get_field", bytelen), &bytelen, |b, bytelen| {
            b.iter(|| get_field(DATA, 0, *bytelen));
        });
    }
    group.finish();
}

criterion_group!(benches, from_elem);
criterion_main!(benches);
