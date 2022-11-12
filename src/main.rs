use cfg_if::cfg_if;
use clap::error::ErrorKind;
use clap::{ColorChoice, CommandFactory, Error, Parser};
use colored::*;
use pcap::Capture;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

mod net;

const HELP_NUMBER: &str = "Number of printable characters to display";
const HELP_FILE: &str = "PCAP format input file";
const HELP_BLOCK_PRINT: &str = "Print string blocks without packet info on each line";

#[cfg(feature = "resolve")]
const HELP_RESOLVE_DNS: &str = "Try to resolve addresses";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None, arg_required_else_help = true, color = ColorChoice::Always)]
struct Cli {
    #[clap(short, long = "bytes", value_parser, default_value_t = 7, help = HELP_NUMBER)]
    number: u32,

    #[clap(short, long, value_parser, default_value = "", help = HELP_FILE)]
    file: String,

    #[clap(short, long, value_parser, default_value_t = false, help = HELP_BLOCK_PRINT)]
    block_print: bool,

    #[cfg(feature = "resolve")]
    #[clap(short, long, value_parser, default_value_t = false, help = HELP_RESOLVE_DNS)]
    resolve_dns: bool,
}

fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let mut cmd = Cli::command();

    let file = Path::new(&cli.file);

    if !file.exists() {
        cmd.error(
            ErrorKind::InvalidValue,
            format!("file not found: {}", cli.file),
        )
        .exit();
    }

    let mut cap = match Capture::from_file(file) {
        Ok(cap) => cap,
        Err(err) => cmd.error(ErrorKind::InvalidValue, err).exit(),
    };

    let mut pkt_count = 0;

    let mut resolver: Option<Box<HashMap<IpAddr, String>>>;

    cfg_if! {
        if #[cfg(feature = "resolve")] {
            if cli.resolve_dns {
                resolver = Some(Box::new(HashMap::new()));
            } else {
                resolver = None;
            }
        } else {
            resolver = None;
        }
    }

    while let Ok(pkt) = cap.next_packet() {
        pkt_count += 1;
        let mut printed = false;
        let mut chars = 0;
        let mut partial = String::new();
        for byte in pkt.data {
            let c = *byte as char;
            // TODO: other encodings
            if c.is_ascii() && !c.is_ascii_control() {
                chars += 1;
                if chars > cli.number {
                    print!("{}", c);
                } else {
                    partial.push(c);
                    if chars == cli.number {
                        let mut pktsum: net::PacketSummary;
                        if let Some(ref mut r) = resolver {
                            pktsum = net::PacketSummary::from_packet(&pkt, Some(&mut *r));
                        } else {
                            pktsum = net::PacketSummary::from_packet(&pkt, None);
                        }

                        let idx = pkt_count.to_string().blue();
                        if !printed || !cli.block_print {
                            let pkt_str = pktsum.to_string();
                            print!("[{idx}]{pkt_str}: ");
                            printed = true;
                            if cli.block_print {
                                println!();
                            }
                        }
                        print!("{partial}");
                    }
                }
            } else {
                if chars >= cli.number {
                    println!();
                }
                chars = 0;
                partial.clear();
            }
        }
        if chars >= cli.number {
            println!();
        }
    }
    Ok(())
}
