use pcap::{Device, Capture, Inactive, Active};
use std::fmt::{Display, Formatter};
use std::path::Path;
use crate::lib::packet_parse::PacketParse;

pub struct PacketCapture {}

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
                    let packet_parse = PacketParse::new();
                    packet_parse.parse_packet(packet.data);
                }
            },
            Err(err) => {
                eprintln!("{:?}", err);
            }
        }
    }
}
