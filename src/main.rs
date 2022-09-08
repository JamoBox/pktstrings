use std::path::Path;
use colored::*;
use clap::{
    CommandFactory,
    Parser,
    Error,
    ErrorKind,
};
use pcap::Capture;

mod net;

const HELP_NUMBER: &str = "Number of printable characters to display";
const HELP_FILE: &str = "PCAP format input file";

#[cfg(feature = "resolve")]
const HELP_RESOLVE_DNS: &str = "Try to resolve addresses";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None, arg_required_else_help = true)]
struct Cli {
    #[clap(short, long = "bytes", value_parser, default_value_t = 7, help = HELP_NUMBER)]
    number: u32,

    #[clap(short, long, value_parser, default_value = "", help = HELP_FILE)]
    file: String,

    #[cfg(feature = "resolve")]
    #[clap(short, long, value_parser, default_value_t = false, help = HELP_RESOLVE_DNS)]
    resolve_dns: bool,
}

fn main() -> Result<(), Error>{
    let cli = Cli::parse();
    let mut cmd = Cli::command();

    let file = Path::new(&cli.file);

    if !file.exists() {
        cmd.error(
            ErrorKind::InvalidValue,
            format!("file not found: {}", cli.file),
        ).exit();
    }

    let mut cap = match Capture::from_file(file) {
        Ok(cap) => cap,
        Err(err) => {
            return Err(cmd.error(
                ErrorKind::InvalidValue,
                err,
            ))
        },
    };

    let mut pkt_count = 0;
    while let Ok(pkt) = cap.next_packet() {
        pkt_count += 1;
        let mut printed = false;
        let mut chars = 0;
        let mut partial = String::new();
        let resolve = cfg!(feature = "resolve");
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
                        let pktsum = net::PacketSummary::from_packet(
                            &pkt,
                            resolve,
                        );
                        let idx = pkt_count.to_string().blue();
                        if !printed {
                            println!("[{idx}]{pktsum}:");
                            printed = true;
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
