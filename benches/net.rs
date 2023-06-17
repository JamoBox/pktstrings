use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use pktstrings::net;

mod meta;

fn net(c: &mut Criterion) {
    let mut field_group = c.benchmark_group("Byte Field Conversion");
    for bytelen in 0..16 {
        field_group.throughput(Throughput::Bytes(bytelen as u64));
        field_group.bench_with_input(
            BenchmarkId::new("get_field", bytelen),
            &bytelen,
            |b, bytelen| {
                b.iter(|| net::get_field(meta::DATA, 0, *bytelen));
            },
        );
    }
    field_group.finish();

    let mut parsing_group = c.benchmark_group("Packet Parsing");
    parsing_group.bench_function(
        BenchmarkId::new("from_packet", "IPv4"),
        |b| {
            b.iter(|| net::PacketSummary::from_packet(&meta::REF_V4_PACKET, None));
        }
    );
    parsing_group.bench_function(
        BenchmarkId::new("from_packet", "IPv6"),
        |b| {
            b.iter(|| net::PacketSummary::from_packet(&meta::REF_V6_PACKET, None));
        }
    );
    parsing_group.finish();

    let mut summary_group = c.benchmark_group("Packet Summary");
    summary_group.bench_function(
        BenchmarkId::new("from_packet_and_formatted", "IPv4"),
        |b| {
            b.iter(|| {
                let mut pktsum = net::PacketSummary::from_packet(&meta::REF_V4_PACKET, None);
                pktsum.formatted();
            });
        }
    );
    summary_group.bench_function(
        BenchmarkId::new("from_packet_and_formatted", "IPv6"),
        |b| {
            b.iter(|| {
                let mut pktsum = net::PacketSummary::from_packet(&meta::REF_V6_PACKET, None);
                pktsum.formatted();
            });
        }
    );
    summary_group.finish();
}

criterion_group!(benches, net);
criterion_main!(benches);
