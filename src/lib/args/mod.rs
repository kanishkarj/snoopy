mod capture;

use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg, SubCommand};
use pcap::{Capture, Precision, TimestampType};

use crate::lib::packet_capture::PacketCapture;
use crate::lib::args::capture::CaptureSubcommand;
use std::cell::RefCell;

pub fn parse_cli_args() {

    let capture_subcommand = CaptureSubcommand::new();

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .subcommand(capture_subcommand.get_subcommand())
        .get_matches();

    match matches.subcommand_matches("capture") {
        Some(sub) => {
            if let Some(_) = sub.subcommand_matches("list") {
                match PacketCapture::list_devices() {
                    Ok(pckt_list) => {
                        println!("All Interfaces : ");
                        pckt_list.iter().for_each(|val| println!("* {}", val));
                    },
                    Err(err) => {
                        eprintln!("{:?}", err);
                    }
                }
            } else if let Some(run_args) = sub.subcommand_matches("run") {
                match run_args.value_of("device_handle") {
                    Some(handle) => {
                        let device = Capture::from_device(handle);
                        match device {
                            Ok(device) => {
                                let device = RefCell::new(device);
                                let device = RefCell::new(capture_subcommand.run_args(device, run_args));
                                capture_subcommand.start(device, run_args);
                            },
                            Err(err) => {
                                eprintln!("{:?}",err);
                            },
                        }
                    },
                    None => {

                    }
                }
            }
        },
        None => {}
    };
}