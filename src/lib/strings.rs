use colored::Colorize;
use pcap::{Activated, Capture};
use regex::bytes::Regex;

use crate::net;

/// Dump any valid ASCII strings over `len` size to stdout.
///
/// If `resolver` is passed in, this function will use it to perform DNS
/// lookups on addresses.
///
/// If `block_print` is set, the function will only print the packet headers
/// for the first ASCII line found.
///
/// If `regex` is provided this is run against the entire packet before
/// the string scanning is run. Packets not matching the regex are skipped.
pub fn dump_strings<T: Activated>(
    cap: &mut Capture<T>,
    len: &usize,
    resolver: &mut Option<Box<net::Resolver>>,
    block_print: &bool,
    regex: &Option<Regex>,
) {
    let mut pkt_count = 0;

    while let Ok(pkt) = cap.next_packet() {
        pkt_count += 1;

        if let Some(regex) = regex {
            if !regex.is_match(pkt.data) {
                continue;
            }
        }

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
