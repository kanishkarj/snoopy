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
            Arg::with_name("file_name")
                .required(true)
        ];

        SubCommand::with_name("parse")
            .about("Parse pcap files.")
            .args(&parse_args)
    }

    pub fn start(&self, args: &ArgMatches) {
        if let Some(val) = args.value_of("file_name") {
            match Capture::from_file(val) {
                Ok(mut cap_handle) => {
                    while let Ok(packet) = cap_handle.next() {
                        println!("{:?}", packet);
                    }
                },
                Err(err) => {
                    eprintln!("{:?}", err);
                }
            }
        }
    }
}