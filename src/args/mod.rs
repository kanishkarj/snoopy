mod capture;
mod parse;

use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg, SubCommand};
use pcap::{Capture, Precision, TimestampType, Device};

use crate::lib::packet_capture::PacketCapture;
use crate::args::capture::CaptureSubcommand;
use std::cell::RefCell;
use crate::args::parse::ParseSubcommand;

fn print_default_device(name: String) {
    println!(
        "{:-^1$}", "-", 20,
    );
    println!("Sniffing  {}", name);
    println!(
        "{:-^1$} \n\n", "-", 20,
    );
}

pub fn parse_cli_args() {

    let capture_subcommand = CaptureSubcommand::new();
    let parse_subcommand = ParseSubcommand::new();

    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .subcommand(capture_subcommand.get_subcommand())
        .subcommand(parse_subcommand.get_subcommand())
        .get_matches();

    match matches.subcommand_matches("capture") {
        Some(sub) => {
            if let Some(_) = sub.subcommand_matches("list") {
                if let Err(err) = PacketCapture::list_devices() {
                    eprintln!("{}", err.to_string())
                }
            } else if let Some(run_args) = sub.subcommand_matches("run") {
                let device;

                match run_args.value_of("device_handle") {
                    Some(handle) => {
                        device = Capture::from_device(handle);
                    },
                    None => {
                        let capture_device = Device::lookup().unwrap();
                        print_default_device(capture_device.name.clone());
                        device = Capture::from_device(capture_device);
                    }
                }

                match device {
                    Ok(device) => {
                        let device = RefCell::new(device);
                        let device = RefCell::new(capture_subcommand.run_args(device, run_args));
                        capture_subcommand.start(device, run_args);
                    },
                    Err(err) => {
                        eprintln!("{}", err.to_string());
                    },
                }
            }
        },
        None => {}
    };

    match matches.subcommand_matches("parse") {
        Some(args) => {
            parse_subcommand.start(args);
        },
        None => {}
    };
}