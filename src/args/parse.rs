use crate::lib::packet_capture::PacketCapture;
use clap::{App, Arg, ArgMatches, SubCommand};
use pcap::{Capture, Inactive, Precision, TimestampType};
use std::cell::RefCell;

pub struct ParseSubcommand {}

impl<'a, 'b> ParseSubcommand {
    pub fn new() -> ParseSubcommand {
        ParseSubcommand {}
    }

    pub fn get_subcommand(&self) -> App<'a, 'b> {
        let parse_args = vec![
            Arg::with_name("file_name").required(true),
            Arg::with_name("savefile")
                .help("Parse the packets into JSON and save them to memory.")
                .takes_value(true)
                .short("s")
                .long("savefile"),
        ];

        SubCommand::with_name("parse")
            .about("Parse pcap files.")
            .args(&parse_args)
    }

    pub fn start(&self, args: &ArgMatches) {
        let mut save_file_path = None;
        let packet_capture = PacketCapture::new();
        if let Some(val) = args.value_of("savefile") {
            save_file_path = Some(val);
        }
        if let Some(val) = args.value_of("file_name") {
            packet_capture.parse_from_file(val, save_file_path);
        }
    }
}
