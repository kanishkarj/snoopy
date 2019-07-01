use packet::{ether, tcp, udp, ip, icmp};
use packet::Packet;
use hwaddr::HwAddr;
use std::net::{Ipv4Addr, Ipv6Addr};
use tls_parser::TlsPlaintext;
use core::borrow::Borrow;

pub struct PacketParse {}

pub struct EthernetFrame {
    pub source_mac: [u8; 6],
    pub dest_mac: [u8; 6],
    pub ethertype: ether::Protocol,
}

pub struct UdpHeader {
    pub source_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub checksum: u16,
}

pub struct TcpHeader {
    pub source_port: u16,
    pub dest_port: u16,
    pub sequence_no: u32,
    pub ack_no: u32,
    pub data_offset: u8,
    pub window: u16,
    pub checksum: u16,
    pub flags: tcp::Flags,
    pub urgent_pointer: u16,
}

pub struct IPv4Header {
    pub version: u8,
    pub length: u16,
    pub id: u16,
    pub flags: ip::v4::Flags,
    pub offset: u16,
    pub ttl: u8,
    pub protocol: ip::Protocol,
    pub chksum: u16,
    pub source_addr: Ipv4Addr,
    pub dest_addr: Ipv4Addr,
    pub header: u8,
    pub dscp: u8,
    pub ecn: u8,
}

pub struct ICMPHeader {
    pub kind: icmp::Kind,
    pub code: u8,
    pub checksum: u16
}

pub struct IPv6Header {}

impl PacketParse {
    pub fn new() -> PacketParse {
        PacketParse{}
    }

    pub fn parse_packet(&self, content: &[u8]) {
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
                                    if let Ok(content) = tls_parser::tls::tls_parser(content.payload()) {
                                        println!("tls");
                                    }
                                }
                            },
                            ip::Protocol::Udp => {
                                if let Ok(content) = udp::Packet::new(content.payload()) {
                                    if let Ok(content) = dns_parser::Packet::parse(content.payload()) {
                                        println!("dns");
                                    }
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

    fn parse_ether(&self, packet_content: &[u8]) -> Result<(EthernetFrame,Vec<u8>), packet::Error>{
        let parsed = ether::Packet::new(packet_content)?;
        return Ok((EthernetFrame{
            dest_mac: parsed.destination().octets(),
            source_mac: parsed.source().octets(),
            ethertype: parsed.protocol(),
        }, parsed.payload().to_owned()));
    }

    fn parse_udp(&self, packet_content: &[u8]) -> Result<(UdpHeader,Vec<u8>), packet::Error>{
        let parsed = udp::Packet::new(packet_content)?;
        return Ok((UdpHeader{
            source_port: parsed.source(),
            dest_port: parsed.destination(),
            length: parsed.length(),
            checksum: parsed.checksum(),
        }, parsed.payload().to_owned()));
    }

    fn parse_tcp(&self, packet_content: &[u8]) -> Result<(TcpHeader,Vec<u8>), packet::Error>{
        let parsed = tcp::Packet::new(packet_content)?;
        return Ok((TcpHeader{
            source_port: parsed.source(),
            dest_port: parsed.destination(),
            sequence_no: parsed.sequence(),
            ack_no: parsed.acknowledgment(),
            data_offset: parsed.offset(),
            window: parsed.window(),
            checksum: parsed.checksum(),
            flags: parsed.flags(),
            urgent_pointer: parsed.pointer(),
        }, parsed.payload().to_owned()));
    }

    fn parse_ipv4(&self, packet_content: &[u8]) -> Result<(IPv4Header,Vec<u8>), packet::Error>{
        let parsed = ip::v4::Packet::new(packet_content)?;
        return Ok((IPv4Header{
            version: parsed.version(),
            length: parsed.length(),
            id: parsed.id(),
            flags: parsed.flags(),
            offset: parsed.offset(),
            ttl: parsed.ttl(),
            protocol: parsed.protocol(),
            chksum: parsed.checksum(),
            source_addr: parsed.source(),
            dest_addr: parsed.destination(),
            header: parsed.header(),
            dscp: parsed.dscp(),
            ecn: parsed.ecn()
        }, parsed.payload().to_owned()));
    }

    fn parse_ipv6(&self, packet_content: &[u8]) -> Result<(IPv6Header,Vec<u8>), packet::Error>{
        let parsed = ip::v6::Packet::new(packet_content)?;
        return Ok((IPv6Header{}, parsed.payload().to_owned()));
    }

    fn parse_dns<'a>(&'a self, packet_content: &'a [u8]) -> Result<dns_parser::Packet,dns_parser::Error>{
        let parsed = dns_parser::Packet::parse(packet_content)?;
        return Ok(parsed);
    }

    fn parse_tls<'a>(&'a self, packet_content: &'a [u8]) -> Result<(TlsPlaintext,Vec<u8>), nom::Err<&'a [u8]>>{
        let parsed = tls_parser::tls::tls_parser(packet_content)?;
        return Ok((parsed.1, parsed.0.to_owned()));
    }

    fn parse_icmp<'a>(&'a self, packet_content: &'a [u8]) -> Result<(ICMPHeader,Vec<u8>), packet::Error>{
        let parsed = icmp::Packet::new(packet_content)?;
        return Ok((ICMPHeader{
            kind: parsed.kind(),
            code: parsed.code(),
            checksum: parsed.checksum()
        }, parsed.payload().to_owned()));
    }
}