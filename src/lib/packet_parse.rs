use pktparse::*;
use pktparse::ethernet::{EtherType, EthernetFrame};
use pktparse::ipv4::IPv4Header;
use pktparse::ip::IPProtocol;
use pktparse::arp::ArpPacket;
use pktparse::tcp::TcpHeader;
use pktparse::udp::UdpHeader;
use pktparse::ipv6::IPv6Header;
use tls_parser::TlsMessage;

use serde::{Deserialize, Serialize};

pub struct PacketParse {}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum PacketHeader {
    Tls(TlsType),
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Ipv4(IPv4Header),
    Ipv6(IPv6Header),
    Ether(EthernetFrame),
    Arp(ArpPacket),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParsedPacket {
    pub headers: Vec<PacketHeader>,
    pub remaining: Vec<u8>,
}

impl ParsedPacket {
    pub fn new() -> ParsedPacket {
        ParsedPacket {
            headers: vec![],
            remaining: vec![]
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum TlsType {
    Handshake,
    ChangeCipherSpec,
    Alert,
    ApplicationData,
    Heartbeat,
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
                EtherType::IPv4 | EtherType::Other(0) => {
                    self.parse_ipv4(content,&mut pack);
                },
                EtherType::IPv6 => {
                    self.parse_ipv6(content,&mut pack);
                },
                EtherType::ARP => {
                    self.parse_arp(content, &mut pack);
                },
                _ => {
                    pack.remaining = content.to_owned();
                },
            }
                pack.headers.push(PacketHeader::Ether(headers));
            },
            Err(_) => {
                pack.remaining = content.to_owned();
            }
        }
        return pack;
    }

    pub fn parse_ipv4(&self, content: &[u8], parsed_packet: &mut ParsedPacket) {
        match  ipv4::parse_ipv4_header(content) {
            Ok((content, headers)) => {
                self.parse_ip(content, parsed_packet);
                parsed_packet.headers.push(PacketHeader::Ipv4(headers));
            },
            Err(_) => {
                parsed_packet.remaining = content.to_owned();
            }
        }
    }

    pub fn parse_ipv6(&self, content: &[u8], parsed_packet: &mut ParsedPacket) {
        match  ipv6::parse_ipv6_header(content) {
            Ok((content, headers)) => {
                self.parse_ip(content, parsed_packet);
                parsed_packet.headers.push(PacketHeader::Ipv6(headers));
            },
            Err(_) => {
                parsed_packet.remaining = content.to_owned();
            }
        }
    }

    fn parse_ip(&self, content: &[u8], parsed_packet: &mut ParsedPacket) {
        if let Ok(_) = self.parse_tcp(content,parsed_packet) {}
        else if let Ok(_) = self.parse_udp(content,parsed_packet) {}
        else {
            parsed_packet.remaining = content.to_owned();
        }
    }

    fn parse_tcp(&self, content: &[u8], parsed_packet: &mut ParsedPacket) -> Result<(),()> {
        match tcp::parse_tcp_header(content) {
            Ok((content, headers)) => {
                self.parse_tls(content, parsed_packet);
                parsed_packet.headers.push(PacketHeader::Tcp(headers));
                Ok(())
            }
            Err(_) => {
                parsed_packet.remaining = content.to_owned();
                Err(())
            }
        }
    }

    fn parse_udp(&self, content: &[u8], parsed_packet: &mut ParsedPacket) -> Result<(),()> {
        match udp::parse_udp_header(content) {
            Ok((content, headers)) => {
                parsed_packet.headers.push(PacketHeader::Udp(headers));
                parsed_packet.remaining = content.to_owned();
                Ok(())
            }
            Err(_) => {
                parsed_packet.remaining = content.to_owned();
                Err(())
            }
        }
    }

    fn parse_arp(&self, content: &[u8], parsed_packet: &mut ParsedPacket) {
        match arp::parse_arp_pkt(content) {
            Ok((content, headers)) => {
                parsed_packet.headers.push(PacketHeader::Arp(headers));
            }
            Err(_) => {
                parsed_packet.remaining = content.to_owned();
            }
        }
    }

    fn parse_tls(&self, content: &[u8], parsed_packet: &mut ParsedPacket) {
        match tls_parser::parse_tls_plaintext(content) {
            Ok((content, headers)) => {
                // Here we return after parsing one msg as we do not want multiple TLS headers, maybe there is a better approach.
                for msg in headers.msg {
                    match msg {
                        TlsMessage::Handshake(_) => {
                            parsed_packet.headers.push(PacketHeader::Tls(TlsType::Handshake));
                            return;
                        },
                        TlsMessage::ApplicationData(app_data) => {
                            parsed_packet.headers.push(PacketHeader::Tls(TlsType::ApplicationData));
                            parsed_packet.remaining = app_data.blob.to_owned();
                            return;
                        },
                        TlsMessage::Heartbeat(_) => {
                            parsed_packet.headers.push(PacketHeader::Tls(TlsType::Heartbeat));
                            return;
                        },
                        TlsMessage::ChangeCipherSpec => {
                            parsed_packet.headers.push(PacketHeader::Tls(TlsType::ChangeCipherSpec));
                            return;
                        },
                        TlsMessage::Alert(_) => {
                            parsed_packet.headers.push(PacketHeader::Tls(TlsType::Alert));
                            return;
                        },
                    }
                }
            }
            Err(_) => {
                parsed_packet.remaining = content.to_owned();
            }
        }
    }

}