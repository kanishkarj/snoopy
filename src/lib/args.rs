use clap::{crate_authors, crate_description, crate_name, crate_version, App, Arg, SubCommand};
use pcap::{Capture, Precision, TimestampType};

use crate::lib::packet_capture::PacketCapture;

fn is_tstamp_type(val: String) -> Result<(), String> {
    let domain_set = vec!["Host","HostLowPrec","HostHighPrec","Adapter","AdapterUnsynced"];
    if domain_set.contains(&&val[..]){
        Ok(())
    } else {
        Err(String::from(format!("The value must be one of {:?}", domain_set)))
    }
}

fn is_precision_type(val: String) -> Result<(), String> {
    let domain_set = vec!["Micro","Nano"];
    if domain_set.contains(&&val[..]){
        Ok(())
    } else {
        Err(String::from(format!("The value must be one of {:?}", domain_set)))
    }
}

fn get_precision_type(val: &str) -> Result<Precision, ()> {
    match val {
        "Micro" => { Ok(Precision::Nano) },
        "Nano" => { Ok(Precision::Nano) },
        _ => { Err(()) }
    }
}

fn get_tstamp_type(val: &str) -> Result<TimestampType, ()> {
    match val {
        "Host" => { Ok(TimestampType::Host) },
        "HostLowPrec" => { Ok(TimestampType::HostLowPrec) },
        "HostHighPrec" => { Ok(TimestampType::HostHighPrec) },
        "Adapter" => { Ok(TimestampType::Adapter) },
        "AdapterUnsynced" => { Ok(TimestampType::AdapterUnsynced) },
        _ => { Err(()) }
    }
}

// TODO : add validators to all other args too
pub fn parse_cli_args() {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .subcommand(SubCommand::with_name("capture")
            .about("Capture packets from interfaces.")
            .subcommand(SubCommand::with_name("list")
                .about("List all interfaces.")
            )
            .subcommand(SubCommand::with_name("run")
                .about("Start capturing packets.")
                .arg(Arg::with_name("device_handle")
                    .required(true))
                .arg(Arg::with_name("timeout")
                    .help("Set the read timeout for the Capture. By default, this is 0, so it will block indefinitely.")
                    .takes_value(true)
                    .short("t")
                    .long("timeout"))
                .arg(Arg::with_name("promisc")
                    .help("Set promiscuous mode on or off. By default, this is off.")
                    .short("p")
                    .long("promisc"))
                .arg(Arg::with_name("rfmon")
                    .help("Set rfmon mode on or off. The default is maintained by pcap.")
                    .short("r")
                    .long("rfmon"))
                .arg(Arg::with_name("buffer_size")
                    .help("Set the buffer size for incoming packet data. The default is 1000000. This should always be larger than the snaplen.")
                    .takes_value(true)
                    .short("b")
                    .long("buffer_size"))
                .arg(Arg::with_name("snaplen")
                    .help("Set the snaplen size (the maximum length of a packet captured into the buffer). \
                    Useful if you only want certain headers, but not the entire packet.The default is 65535.")
                    .takes_value(true)
                    .short("s")
                    .long("snaplen"))
                .arg(Arg::with_name("precision")
                    .help("Set the time stamp precision returned in captures (Micro/Nano).")
                    .takes_value(true)
                    .long("precision")
                    .validator(is_precision_type))
                .arg(Arg::with_name("tstamp_type")
                    .help("Set the time stamp type to be used by a capture device \
                    (Host / HostLowPrec / HostHighPrec / Adapter / AdapterUnsynced).")
                    .takes_value(true)
                    .long("tstamp_type")
                    .validator(is_tstamp_type))
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
                    Err(err) => {
                        eprintln!("{:?}", err);
                    }
                }
            } else if let Some(run_args) = sub.subcommand_matches("run") {
                match run_args.value_of("device_handle") {
                    Some(handle) => {
                        let mut device = Capture::from_device(handle);
                        match device {
                            Ok(mut device) => {
                                // the validators will ensure we are passing the proper type, hence using unwrap is not a problem.
                                if let Some(val) = run_args.value_of("timeout") {
                                    device = device.timeout(val.parse().unwrap());
                                }
                                if let Some(val) = run_args.value_of("promisc") {
                                    device = device.promisc(val.parse().unwrap());
                                }
                                if let Some(val) = run_args.value_of("rfmon") {
                                    device = device.rfmon(val.parse().unwrap());
                                }
                                if let Some(val) = run_args.value_of("buffer_size") {
                                    device = device.buffer_size(val.parse().unwrap());
                                }
                                if let Some(val) = run_args.value_of("snaplen") {
                                    device = device.snaplen(val.parse().unwrap());
                                }
                                if let Some(val) = run_args.value_of("precision") {
                                    device = device.precision(get_precision_type(val).unwrap());
                                }
                                if let Some(val) = run_args.value_of("tstamp_type") {
                                    device = device.tstamp_type(get_tstamp_type(val).unwrap());
                                }
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