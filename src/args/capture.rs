use crate::lib::packet_capture::PacketCapture;
use clap::{App, Arg, ArgMatches, SubCommand};
use pcap::{Capture, Inactive, Precision, TimestampType};
use std::cell::RefCell;

fn is_tstamp_type(val: String) -> Result<(), String> {
    let domain_set = vec![
        "Host",
        "HostLowPrec",
        "HostHighPrec",
        "Adapter",
        "AdapterUnsynced",
    ];
    if domain_set.contains(&&val[..]) {
        Ok(())
    } else {
        Err(format!("The value must be one of {:?}", domain_set))
    }
}

fn is_i32(val: String) -> Result<(), String> {
    match val.parse::<i32>() {
        Ok(_) => Ok(()),
        Err(err) => Err(err.to_string()),
    }
}

fn is_precision_type(val: String) -> Result<(), String> {
    let domain_set = vec!["Micro", "Nano"];
    if domain_set.contains(&&val[..]) {
        Ok(())
    } else {
        Err(format!("The value must be one of {:?}", domain_set))
    }
}

pub struct CaptureSubcommand {}

impl<'a, 'b> CaptureSubcommand {
    pub fn new() -> CaptureSubcommand {
        CaptureSubcommand {}
    }

    pub fn get_subcommand(&self) -> App<'a, 'b> {
        let run_args = vec![
            Arg::with_name("device_handle")
                .help("Specify the device interface")
                .takes_value(true)
                .long("handle"),
            Arg::with_name("timeout")
                .help("Set the read timeout for the Capture. By default, this is 0, so it will block indefinitely.")
                .takes_value(true)
                .short("t")
                .long("timeout")
                .validator(is_i32),
            Arg::with_name("promisc")
                .help("Set promiscuous mode on or off. By default, this is off.")
                .short("p")
                .long("promisc"),
            Arg::with_name("rfmon")
                .help("Set rfmon mode on or off. The default is maintained by pcap.")
                .short("r")
                .long("rfmon"),
            Arg::with_name("buffer_size")
                .help("Set the buffer size for incoming packet data. The default is 1000000. This should always be larger than the snaplen.")
                .takes_value(true)
                .short("b")
                .long("buffer_size")
                .validator(is_i32),
            Arg::with_name("snaplen")
                .help("Set the snaplen size (the maximum length of a packet captured into the buffer). \
                    Useful if you only want certain headers, but not the entire packet.The default is 65535.")
                .takes_value(true)
                .short("s")
                .long("snaplen")
                .validator(is_i32),
            Arg::with_name("precision")
                .help("Set the time stamp precision returned in captures (Micro/Nano).")
                .takes_value(true)
                .long("precision")
                .validator(is_precision_type),
            Arg::with_name("tstamp_type")
                .help("Set the time stamp type to be used by a capture device \
                    (Host / HostLowPrec / HostHighPrec / Adapter / AdapterUnsynced).")
                .takes_value(true)
                .long("tstamp_type")
                .validator(is_tstamp_type),
            Arg::with_name("filter")
                .help("Set filter to the capture using the given BPF program string.")
                .takes_value(true)
                .long("filter")
                .short("f"),
            Arg::with_name("savefile")
                .help("Save the captured packets to file.")
                .takes_value(true)
                .long("savefile")
        ];

        SubCommand::with_name("capture")
            .about("Capture packets from interfaces.")
            .subcommand(SubCommand::with_name("list").about("List all interfaces."))
            .subcommand(
                SubCommand::with_name("run")
                    .about("Start capturing packets.")
                    .args(&run_args),
            )
    }

    pub fn run_args(
        &self,
        device: RefCell<Capture<Inactive>>,
        args: &ArgMatches,
    ) -> RefCell<Capture<Inactive>> {
        let mut device = device.into_inner();
        // the validators will ensure we are passing the proper type, hence using unwrap is not a problem.
        if let Some(val) = args.value_of("timeout") {
            device = device.timeout(val.parse().unwrap());
        }
        if let Some(val) = args.value_of("promisc") {
            device = device.promisc(val.parse().unwrap());
        }
        if let Some(val) = args.value_of("rfmon") {
            device = device.rfmon(val.parse().unwrap());
        }
        if let Some(val) = args.value_of("buffer_size") {
            device = device.buffer_size(val.parse().unwrap());
        }
        if let Some(val) = args.value_of("snaplen") {
            device = device.snaplen(val.parse().unwrap());
        }
        if let Some(val) = args.value_of("precision") {
            device = device.precision(self.get_precision_type(val).unwrap());
        }
        if let Some(val) = args.value_of("tstamp_type") {
            device = device.tstamp_type(self.get_tstamp_type(val).unwrap());
        }
        if let Some(val) = args.value_of("tstamp_type") {
            device = device.tstamp_type(self.get_tstamp_type(val).unwrap());
        }
        RefCell::new(device)
    }

    pub fn start(&self, device: RefCell<Capture<Inactive>>, args: &ArgMatches) {
        let device = device.into_inner();
        let packet_capture = PacketCapture::new();

        match device.open() {
            Ok(mut cap_handle) => {
                // Set pacp capture filters
                if let Some(val) = args.value_of("filter") {
                    cap_handle
                        .filter(val)
                        .expect("Filters invalid, please check the documentation.");
                }

                // To select between saving to file and printing to console.
                if let Some(val) = args.value_of("savefile") {
                    packet_capture.save_to_file(cap_handle, val);
                } else {
                    packet_capture.print_to_console(cap_handle);
                }
            }
            Err(err) => {
                eprintln!("{:?}", err);
            }
        }
    }

    fn get_precision_type(&self, val: &str) -> Result<Precision, ()> {
        match val {
            "Micro" => Ok(Precision::Nano),
            "Nano" => Ok(Precision::Nano),
            _ => Err(()),
        }
    }

    fn get_tstamp_type(&self, val: &str) -> Result<TimestampType, ()> {
        match val {
            "Host" => Ok(TimestampType::Host),
            "HostLowPrec" => Ok(TimestampType::HostLowPrec),
            "HostHighPrec" => Ok(TimestampType::HostHighPrec),
            "Adapter" => Ok(TimestampType::Adapter),
            "AdapterUnsynced" => Ok(TimestampType::AdapterUnsynced),
            _ => Err(()),
        }
    }
}
