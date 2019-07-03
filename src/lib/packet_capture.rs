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

pub struct PacketCapture {
    threadpool: ThreadPool
}

impl PacketCapture {

    pub fn new() -> PacketCapture {
        PacketCapture {
            threadpool: ThreadPool::new( num_cpus::get() * 2 )
        }
    }

    pub fn list_devices() -> Result<Vec<String>, pcap::Error> {
        Ok(Device::list()?
            .iter()
            .map(|val| val.name.clone())
            .collect())
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
        while let Ok(packet) = cap_handle.next() {
            let data = packet.data.to_owned();
            let len = packet.header.len;
            let ts = packet.header.ts.tv_sec;

            pool.execute(move || {
                let packet_parse = PacketParse::new();
                let parsed_packet = packet_parse.parse_packet(data, len,  ts);
                println!("{:?}", parsed_packet);
            });
        }
    }

    fn get_packet_meta(&self, parsed_packet : ParsedPacket) -> (Option<IpAddr>, Option<u16>, Option<IpAddr>, Option<u16>){

        let mut src_addr: Option<_> = None;
        let mut dst_addr: Option<_> = None;
        let mut src_port: Option<_> = None;
        let mut dst_port: Option<_> = None;

        parsed_packet.headers.iter().for_each(|pack| {
            match pack {
                PacketHeader::Tcp(packet) => {
                    src_port = Some(packet.source_port);
                    dst_port = Some(packet.dest_port);
                },
                PacketHeader::Udp(packet) => {
                    src_port = Some(packet.source_port);
                    dst_port = Some(packet.dest_port);
                },
                PacketHeader::Ipv4(packet) => {
                    src_addr = Some(IpAddr::V4(packet.source_addr));
                    dst_addr = Some(IpAddr::V4(packet.dest_addr));
                },
                PacketHeader::Ipv6(packet) => {
                    src_addr = Some(IpAddr::V6(packet.source_addr));
                    dst_addr = Some(IpAddr::V6(packet.dest_addr));
                },
                _ => {}
            }
        });

        return (src_addr, src_port, dst_addr, dst_port);
    }

    fn format_output(&self, parsed_packet : ParsedPacket) {
        println!("{:?}", parsed_packet);
    }

    pub fn parse_from_file(&self, file_name: &str, save_file_path: Option<&str>) {
        let pool = ThreadPool::new( num_cpus::get() * 2 );
        match Capture::from_file(file_name) {
            Ok(mut cap_handle) => {
                let mut packets = Arc::new(Mutex::new(Vec::new()));

                while let Ok(packet) = cap_handle.next() {

                    let data = packet.data.to_owned();
                    let len = packet.header.len;
                    let ts = packet.header.ts.tv_sec;

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
                    println!("{:?}", *packets);
                }
            },
            Err(err) => {
                eprintln!("{:?}", err);
            }
        }
    }
}
