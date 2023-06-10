use cfg_if::cfg_if;
use clap::error::ErrorKind;
use clap::{ColorChoice, CommandFactory, Parser};
use colored::*;
use pcap::{Activated, Capture, Device};
use regex::bytes::Regex;
use std::path::Path;
use std::vec::Vec;

mod net;
mod proto;

const HELP_NUMBER: &str = "Number of printable characters to display";
const HELP_BLOCK_PRINT: &str = "Print string blocks without packet info on each line";
const HELP_BPF_EXPRESSION: &str = "BPF expression to filter packets with";
const HELP_RGX_EXPRESSION: &str = "Regular expression to match strings against";
const HELP_LIST_DEVICES: &str = "List available network devices to read packets from";
const HELP_FILE: &str = "PCAP format input file to read packets from";
const HELP_INTERFACE: &str = "Network device to read packets from";

#[cfg(feature = "resolve")]
const HELP_RESOLVE_DNS: &str = "Try to resolve addresses (Warning: SLOW!)";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about, color = ColorChoice::Always)]
struct Cli {
    #[clap(short, long = "bytes", value_parser, default_value_t = 7, help = HELP_NUMBER)]
    number: usize,

    #[clap(short, long, value_parser, default_value_t = false, help = HELP_BLOCK_PRINT)]
    block_print: bool,

    #[clap(short = 'e', long, value_parser, help = HELP_BPF_EXPRESSION)]
    bpf_expression: Option<String>,

    #[cfg(feature = "resolve")]
    #[clap(short, long, value_parser, default_value_t = false, help = HELP_RESOLVE_DNS)]
    resolve_dns: bool,

    #[clap(short, long, value_parser, default_value_t = false, exclusive = true, help = HELP_LIST_DEVICES)]
    list_devices: bool,

    #[clap(short, long, value_parser, help = HELP_RGX_EXPRESSION)]
    search_expression: Option<String>,

    #[clap(
        short,
        long,
        value_parser,
        help = HELP_FILE,
    )]
    file: Option<String>,

    #[clap(
        short,
        long,
        value_parser,
        help = HELP_INTERFACE,
    )]
    interface: Option<String>,
}

/// Applys the provided BPF filter to the capture file.
fn apply_filter<T: Activated>(cap: &mut Capture<T>, bpf: &Option<String>, cmd: &mut clap::Command) {
    if let Some(bpf) = bpf {
        match cap.filter(bpf, true) {
            Ok(_) => (),
            Err(err) => cmd.error(ErrorKind::InvalidValue, err).exit(),
        }
    }
}

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
fn dump_strings<T: Activated>(
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

/// Print to stdout the available network devices.
fn list_devices() {
    let default_dev = Device::lookup().ok().flatten();
    let devices: Vec<String> = Device::list()
        .unwrap_or_default()
        .iter()
        .map(|x| x.name.clone())
        .collect();
    for dev in devices.iter() {
        if let Some(default_dev) = &default_dev {
            if *dev == *default_dev.name {
                let dev = dev.to_string().bold();
                print!("{dev}");
            } else {
                print!("{dev}");
            }
        } else {
            print!("{dev}");
        }
        print!("\t");
    }
    println!();
}

fn main() -> Result<(), clap::Error> {
    let cli = Cli::parse();
    let mut cmd = Cli::command();

    if cli.list_devices {
        list_devices();
        return Ok(());
    }

    let mut regex: Option<Regex> = None;
    if let Some(re) = cli.search_expression {
        regex = match Regex::new(&re) {
            Ok(expr) => Some(expr),
            Err(err) => cmd.error(ErrorKind::InvalidValue, err).exit(),
        }
    }

    let mut resolver: Option<Box<net::Resolver>>;
    cfg_if! {
        if #[cfg(feature = "resolve")] {
            if cli.resolve_dns {
                resolver = Some(Box::default());
            } else {
                resolver = None;
            }
        } else {
            resolver = None;
        }
    }

    if cli.file.is_some() {
        let file = &cli.file.unwrap();
        let filepath = Path::new(file);

        if !filepath.exists() {
            let err = format!("file not found: {file}");
            cmd.error(ErrorKind::InvalidValue, err).exit();
        }

        match Capture::from_file(file) {
            Ok(mut cap) => {
                apply_filter(&mut cap, &cli.bpf_expression, &mut cmd);
                dump_strings(
                    &mut cap,
                    &cli.number,
                    &mut resolver,
                    &cli.block_print,
                    &regex,
                );
            }
            Err(err) => cmd.error(ErrorKind::InvalidValue, err).exit(),
        };
    } else if cli.interface.is_some() {
        let intf = cli.interface.unwrap();
        let mut devices: Vec<Device> = vec![];

        devices.append(&mut Device::list().unwrap_or_default());

        if let Some(dev) = devices.iter().find(|&x| x.name == intf) {
            let capture_dev = match Capture::from_device(dev.clone()) {
                Ok(cap) => cap.immediate_mode(true),
                Err(err) => cmd.error(ErrorKind::Io, err).exit(),
            };
            match capture_dev.open() {
                Ok(mut cap) => {
                    apply_filter(&mut cap, &cli.bpf_expression, &mut cmd);
                    dump_strings(
                        &mut cap,
                        &cli.number,
                        &mut resolver,
                        &cli.block_print,
                        &regex,
                    );
                }
                Err(err) => cmd.error(ErrorKind::Io, err).exit(),
            };
        } else {
            let err = format!("device not found: {intf}");
            cmd.error(ErrorKind::InvalidValue, err).exit();
        }
    } else {
        let capture_dev = match Device::lookup() {
            Ok(maybe_dev) => match maybe_dev {
                Some(dev) => dev,
                None => cmd.error(ErrorKind::Io, "no devices found").exit(),
            },
            Err(err) => cmd.error(ErrorKind::Io, err).exit(),
        };
        match Capture::from_device(capture_dev) {
            Ok(inactive_cap) => match inactive_cap.immediate_mode(true).open() {
                Ok(mut cap) => {
                    apply_filter(&mut cap, &cli.bpf_expression, &mut cmd);
                    dump_strings(
                        &mut cap,
                        &cli.number,
                        &mut resolver,
                        &cli.block_print,
                        &regex,
                    );
                }
                Err(err) => cmd.error(ErrorKind::Io, err).exit(),
            },
            Err(err) => cmd.error(ErrorKind::Io, err).exit(),
        };
    }

    Ok(())
}
