use pcap::{Device, Capture, Inactive, Active};
use std::fmt::{Display, Formatter};
use std::path::Path;

use packet::{ether, tcp, udp, ip, icmp};
use packet::Packet;
pub struct PacketCapture {}

fn parse_packet(content: &[u8]) {
    if let Ok(content)  = ether::Packet::new(content) {
        println!("ether");
        match content.protocol() {
            ether::Protocol::Ipv4 => {
                if let Ok(content) = ip::v4::Packet::new(content.payload()) {
                    println!("ipv4");
                    match content.protocol() {
                        ip::Protocol::Icmp => {
                            if let Ok(content) = icmp::Packet::new(content.payload()) {
                                println!("icmp");
                            }
                        },
                        ip::Protocol::Tcp => {
                            if let Ok(content) = tcp::Packet::new(content.payload()) {
                                println!("{:?}", content);
                            }
                        },
                        ip::Protocol::Udp => {
                            if let Ok(content) = udp::Packet::new(content.payload()) {
                                println!("{:?}", content);
                            }
                        },
                        _ => {}
                    }
                }
            },
            ether::Protocol::Ipv6 => {
                if let Ok(content) = ip::v6::Packet::new(content.payload()) {
                    println!("ipv6");
                }
            },
            _ => {}
        }
    }

    println!("");
}

impl PacketCapture {

    pub fn new() -> PacketCapture {
        PacketCapture {}
    }

    pub fn list_devices() -> Result<Vec<String>, pcap::Error> {
        Ok(Device::list()?
            .iter()
            .map(|val| val.name.clone())
            .collect())
    }

    pub fn save_to_file(mut cap_handle: Capture<Active>, file_name: &str) {
        match cap_handle.savefile(&file_name) {
            Ok(mut file) => {
                while let Ok(packet) = cap_handle.next() {
                    file.write(&packet);
                }
            },
            Err(err) => {
                eprintln!("{:?}", err);
            }
        }
    }

    pub fn print_to_console(mut cap_handle: Capture<Active>) {
        while let Ok(packet) = cap_handle.next() {
            println!("{:?}", packet);
        }
    }

    pub fn parse_from_file(file_name: &str) {
        match Capture::from_file(file_name) {
            Ok(mut cap_handle) => {
                while let Ok(packet) = cap_handle.next() {
//                    println!("{:?}", packet);
                    parse_packet(packet.data);
                }
            },
            Err(err) => {
                eprintln!("{:?}", err);
            }
        }
    }
}
