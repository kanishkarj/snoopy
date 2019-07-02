use pktparse::*;
use pktparse::ethernet::{EtherType, EthernetFrame};
use pktparse::ipv4::IPv4Header;
use pktparse::ip::IPProtocol;
use pktparse::arp::ArpPacket;
use pktparse::tcp::TcpHeader;
use pktparse::udp::UdpHeader;
use pktparse::ipv6::IPv6Header;

use serde::{Deserialize, Serialize};

pub struct PacketParse {}

#[derive(Debug, Serialize, Deserialize)]
pub enum PacketHeader {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Ipv4(IPv4Header),
    Ipv6(IPv6Header),
    Ether(EthernetFrame),
    Arp(ArpPacket),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParsedPacket {
    headers: Vec<PacketHeader>,
}

impl ParsedPacket {
    pub fn new() -> ParsedPacket {
        ParsedPacket {
            headers: vec![]
        }
    }
}

impl PacketParse {
    pub fn new() -> PacketParse {
        PacketParse{}
    }

    pub fn parse_packet(&self, content: &[u8]) -> ParsedPacket {
        self.parse_link_layer(content)
    }

    pub fn parse_link_layer(&self, content: &[u8]) -> ParsedPacket {
        let mut pack = ParsedPacket::new();
        match  ethernet::parse_ethernet_frame(content) {
            Ok((content, headers)) => {
                match headers.ethertype {
                EtherType::IPv4 => {
                    self.parse_ipv4(content,&mut pack);
                },
                EtherType::IPv6 => {
                    self.parse_ipv6(content,&mut pack);
                },
                EtherType::ARP => {
                    self.parse_arp(content, &mut pack);
                },
                _ => {

                },
            }
                pack.headers.push(PacketHeader::Ether(headers));
            },
            Err(_) => {}
        }
        return pack;
    }

    pub fn parse_ipv4(&self, content: &[u8], parsed_packet: &mut ParsedPacket) {
        match  ipv4::parse_ipv4_header(content) {
            Ok((content, headers)) => {
                self.parse_ip(&headers.protocol, content, parsed_packet);
                parsed_packet.headers.push(PacketHeader::Ipv4(headers));
            },
            Err(_) => {}
        }
    }

    pub fn parse_ipv6(&self, content: &[u8], parsed_packet: &mut ParsedPacket) {
        match  ipv6::parse_ipv6_header(content) {
            Ok((content, headers)) => {
                self.parse_ip(&headers.next_header, content, parsed_packet);
                parsed_packet.headers.push(PacketHeader::Ipv6(headers));
            },
            Err(_) => {}
        }
    }

    fn parse_ip(&self, protocol: &IPProtocol, content: &[u8], parsed_packet: &mut ParsedPacket) {
        if let Ok(_) = self.parse_tcp(content,parsed_packet) {

        } else {
                self.parse_udp(content,parsed_packet);
        }
    }

    fn parse_tcp(&self, content: &[u8], parsed_packet: &mut ParsedPacket) -> Result<(),()> {
        match tcp::parse_tcp_header(content) {
            Ok((content, headers)) => {
                parsed_packet.headers.push(PacketHeader::Tcp(headers));
                Ok(())
            }
            Err(_) => {
                Err(())
            }
        }
    }

    fn parse_udp(&self, content: &[u8], parsed_packet: &mut ParsedPacket) {
        match udp::parse_udp_header(content) {
            Ok((content, headers)) => {
                parsed_packet.headers.push(PacketHeader::Udp(headers));
            }
            Err(_) => {}
        }
    }

    fn parse_arp(&self, content: &[u8], parsed_packet: &mut ParsedPacket) {
        match arp::parse_arp_pkt(content) {
            Ok((content, headers)) => {
                parsed_packet.headers.push(PacketHeader::Arp(headers));
            }
            Err(_) => {}
        }
    }
}