use colored::Colorize;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use pcap::{Activated, Capture};
use std::path::Path;

use pktstrings::net;

const PCAP: &str = "./benches/data/http.pcap";

pub fn print_strings<T: Activated>(
    cap: &mut Capture<T>,
    len: &usize,
    resolver: &mut Option<Box<net::Resolver>>,
    block_print: &bool,
) {
    let mut pkt_count = 0;

    while let Ok(pkt) = cap.next_packet() {
        pkt_count += 1;

        let mut printed = false;
        let mut chars = 0;
        let mut partial = String::new();
        let mut pkt_str: Option<String> = None;
        for byte in pkt.data {
            let c = *byte as char;
            // TODO: other encodings
            if c.is_ascii() && !c.is_ascii_control() {
                chars += 1;
                if chars > *len {
                    print!("{}", c);
                } else {
                    partial.push(c);
                    if chars == *len {
                        if pkt_str.is_none() {
                            if let Some(ref mut r) = resolver {
                                let mut pktsum = net::PacketSummary::from_packet(&pkt, Some(r));
                                pkt_str = Some(pktsum.formatted());
                            } else {
                                let mut pktsum = net::PacketSummary::from_packet(&pkt, None);
                                pkt_str = Some(pktsum.formatted());
                            }
                        }

                        let idx = pkt_count.to_string().blue();
                        if !printed || !*block_print {
                            if let Some(ref mut pkt_str) = pkt_str {
                                print!("[{idx}]{pkt_str}: ");
                                printed = true;
                                if *block_print {
                                    println!();
                                }
                            }
                        }
                        print!("{partial}");
                    }
                }
            } else {
                if chars >= *len {
                    println!();
                }
                chars = 0;
                partial.clear();
            }
        }
        if chars >= *len {
            println!();
        }
    }
}

pub fn buffer_strings<T: Activated>(
    cap: &mut Capture<T>,
    len: &usize,
    resolver: &mut Option<Box<net::Resolver>>,
    block_print: &bool,
) {
    let mut pkt_count = 0;

    while let Ok(pkt) = cap.next_packet() {
        pkt_count += 1;

        let mut found = false;
        let mut chars = 0;
        let mut display_string = String::new();
        let mut partial = String::new();
        let mut pkt_str: Option<String> = None;
        for byte in pkt.data {
            let c = *byte as char;
            // TODO: other encodings
            if c.is_ascii() && !c.is_ascii_control() {
                chars += 1;
                if chars > *len {
                    display_string.push(c);
                } else {
                    partial.push(c);
                    if chars == *len {
                        if pkt_str.is_none() {
                            if let Some(ref mut r) = resolver {
                                let mut pktsum = net::PacketSummary::from_packet(&pkt, Some(r));
                                pkt_str = Some(pktsum.formatted());
                            } else {
                                let mut pktsum = net::PacketSummary::from_packet(&pkt, None);
                                pkt_str = Some(pktsum.formatted());
                            }
                        }

                        let idx = pkt_count.to_string().blue();
                        if !found || !*block_print {
                            if let Some(ref mut pkt_str) = pkt_str {
                                display_string.push_str(format!("[{idx}]{pkt_str}: ").as_str());
                                found = true;
                                if *block_print {
                                    display_string.push('\n');
                                }
                            }
                        }
                        display_string.push_str(partial.as_str());
                        partial.clear();
                    }
                }
            } else {
                // print when we encounter non-ascii
                if chars >= *len {
                    println!("{}", display_string);
                } else {
                    partial.clear();
                    display_string.clear()
                }
                chars = 0;
            }
        }
        // print if we hit end of packet but havent dumped buffer yet
        if chars >= *len {
            println!("{}", display_string);
        }
    }
}

fn dump_strings_benches(c: &mut Criterion) {
    let mut pktstring_group = Criterion::benchmark_group(c, "String Dump Comparisons");
    pktstring_group.bench_function(BenchmarkId::new("print_strings", "http_pcap"), |b| {
        let filepath = Path::new(PCAP);
        let mut cap = Capture::from_file(filepath).unwrap();
        b.iter(|| {
            print_strings(&mut cap, &7, &mut None, &false);
        });
    });
    pktstring_group.bench_function(BenchmarkId::new("buffer_strings", "http_pcap"), |b| {
        let filepath = Path::new(PCAP);
        let mut cap = Capture::from_file(filepath).unwrap();
        b.iter(|| {
            buffer_strings(&mut cap, &7, &mut None, &false);
        });
    });
    pktstring_group.finish();
}

criterion_group!(benches, dump_strings_benches);
criterion_main!(benches);
