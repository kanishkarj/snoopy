use pcap::{Device, Capture, Inactive, Active};
use std::fmt::{Display, Formatter};
use std::path::Path;
use crate::lib::packet_parse::{PacketParse, PacketHeader, ParsedPacket};
use std::fs;
use threadpool::ThreadPool;
use std::sync::mpsc::channel;
use std::iter::FromIterator;
use std::sync::{Arc, Mutex};
use std::net::IpAddr;


pub struct PacketCapture {}

impl PacketCapture {

    pub fn new() -> PacketCapture {
        PacketCapture {}
    }

    pub fn list_devices() -> Result<(), pcap::Error> {
        let devices: Vec<String> = Device::list()?
            .iter()
            .map(|val| val.name.clone())
            .collect();
        println!("All Interfaces : ");
        devices.iter().for_each(|val| println!("* {}", val));
        Ok(())
    }

    pub fn save_to_file(&self, mut cap_handle: Capture<Active>, file_name: &str) {
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

    pub fn print_to_console(&self, mut cap_handle: Capture<Active>) {
        let pool = ThreadPool::new( num_cpus::get() * 2 );

        self.print_headers();

        while let Ok(packet) = cap_handle.next() {

            let data = packet.data.to_owned();
            let len = packet.header.len;
            let ts: String = format!("{}.{:06}", &packet.header.ts.tv_sec, &packet.header.ts.tv_usec);

            let packet_parse = PacketParse::new();
            let parsed_packet = packet_parse.parse_packet(data, len, ts);
            self.format_output(&parsed_packet);
        }
    }

    fn print_headers(&self) {
        println!(
            "{0: <25} | {1: <15} | {2: <25} | {3: <15} | {4: <15} | {5: <15} | {6: <35} |",
            "Source IP", "Source Port", "Dest IP", "Dest Port", "Protocol", "Length", "Timestamp"
        );
        println!(
            "{:-^1$}", "-", 165,
        );
    }

    fn get_packet_meta(&self, parsed_packet : &ParsedPacket) -> (String, String, String, String){

        let mut src_addr = "".to_string();
        let mut dst_addr = "".to_string();
        let mut src_port = "".to_string();
        let mut dst_port = "".to_string();

        parsed_packet.headers.iter().for_each(|pack| {
            match pack {
                PacketHeader::Tcp(packet) => {
                    src_port = packet.source_port.to_string();
                    dst_port = packet.dest_port.to_string();
                },
                PacketHeader::Udp(packet) => {
                    src_port = packet.source_port.to_string();
                    dst_port = packet.dest_port.to_string();
                },
                PacketHeader::Ipv4(packet) => {
                    src_addr = IpAddr::V4(packet.source_addr).to_string();
                    dst_addr = IpAddr::V4(packet.dest_addr).to_string();
                },
                PacketHeader::Ipv6(packet) => {
                    src_addr = IpAddr::V6(packet.source_addr).to_string();
                    dst_addr = IpAddr::V6(packet.dest_addr).to_string();
                },
                PacketHeader::Arp(packet) => {
                    src_addr = packet.src_addr.to_string();
                    dst_addr = packet.dest_addr.to_string();
                },
                _ => {}
            };
        });

        return (src_addr, src_port, dst_addr, dst_port);
    }

    fn format_output(&self, parsed_packet : &ParsedPacket) {
        let (src_addr, src_port, dst_addr, dst_port) = self.get_packet_meta(&parsed_packet);
        let protocol = &parsed_packet.headers[0].to_string();
        let length = &parsed_packet.len;
        let ts = &parsed_packet.timestamp;
        println!("{0: <25} | {1: <15} | {2: <25} | {3: <15} | {4: <15} | {5: <15} | {6: <35}", src_addr, src_port, dst_addr, dst_port, protocol, length, ts);
    }

    pub fn parse_from_file(&self, file_name: &str, save_file_path: Option<&str>) {
        let pool = ThreadPool::new( num_cpus::get() * 2 );
        match Capture::from_file(file_name) {
            Ok(mut cap_handle) => {
                let mut packets = Arc::new(Mutex::new(Vec::new()));

                while let Ok(packet) = cap_handle.next() {

                    let data = packet.data.to_owned();
                    let len = packet.header.len;
                    let ts: String = format!("{}.{:06}", &packet.header.ts.tv_sec, &packet.header.ts.tv_usec);

                    let packets = packets.clone();

                    pool.execute(move || {
                        let packet_parse = PacketParse::new();
                        let parsed_packet = packet_parse.parse_packet(data, len, ts);

                        packets.lock().unwrap().push(parsed_packet);
                    });
                }

                if let Some(path) = save_file_path {
                    let packets = packets.lock().unwrap();
                    let packets = &*packets;
                    let packets = serde_json::to_string(&packets).unwrap();
                    fs::write(path, packets).unwrap();
                } else {
                    let packets = packets.lock().unwrap();

                    self.print_headers();

                    packets.iter().for_each(|pack| {
                        self.format_output(pack);
                    })
                }
            },
            Err(err) => {
                eprintln!("{:?}", err);
            }
        }
    }
}
