mod lib;

use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg, SubCommand};

use lib::packet_capture::PacketCapture;

fn main() {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .subcommand(SubCommand::with_name("capture")
            .about("Capture packets from interfaces.")
            .subcommand(SubCommand::with_name("list")
                .about("List all interfaces.")
            )
        )
        .get_matches();

    match matches.subcommand_matches("capture") {
        Some(sub) => {
            if let Some(_) = sub.subcommand_matches("list") {
                match PacketCapture::list_devices() {
                    Ok(pckt_list) => {
                        println!("All Interfaces : ");
                        pckt_list.iter().for_each(|val| println!("* {}", val));
                    },
                    Err(err) => {}
                }
            }
        },
        None => {}
    };
}
