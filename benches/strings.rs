use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pcap::Capture;
use std::path::Path;

use pktstrings::{net, strings};

const PCAP: &str = "./benches/data/SkypeIRC.cap";

fn str(c: &mut Criterion) {
    let mut pktstring_group = Criterion::benchmark_group(c, "Dump Strings");
    pktstring_group.bench_function(BenchmarkId::new("dump_strings", "defaults_skypeIRC_pcap"), |b| {
        let filepath = Path::new(PCAP);
        let mut cap = Capture::from_file(filepath).unwrap();
        b.iter(|| {
            strings::dump_strings(&mut cap, &7, &mut None, &false, &None);
        });
    });
    pktstring_group.bench_function(BenchmarkId::new("dump_strings", "resolve_skypeIRC_pcap"), |b| {
        let mut resolver: Option<Box<net::Resolver>> = Some(Box::default());
        let filepath = Path::new(PCAP);
        let mut cap = Capture::from_file(filepath).unwrap();
        b.iter(|| {
            strings::dump_strings(&mut cap, &7, &mut resolver, &false, &None);
        });
    });
    pktstring_group.finish();
}

criterion_group!(benches, str);
criterion_main!(benches);
