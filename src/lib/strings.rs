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
