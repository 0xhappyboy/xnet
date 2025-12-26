use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone)]
pub enum Protocol {
    TCP,
    UDP,
    HTTP,
    HTTPS,
    DNS,
    ICMP,
    ARP,
    Other(String),
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::HTTP => write!(f, "HTTP"),
            Protocol::HTTPS => write!(f, "HTTPS"),
            Protocol::DNS => write!(f, "DNS"),
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::ARP => write!(f, "ARP"),
            Protocol::Other(s) => write!(f, "{}", s),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkPacket {
    pub id: u64,
    pub timestamp: String,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub length: usize,
    pub info: String,
    pub raw_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub description: String,
    pub ip_address: String,
    pub mac_address: String,
    pub is_up: bool,
    pub packets_received: u64,
    pub packets_sent: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
}

#[derive(Debug, Clone)]
pub struct PacketDetail {
    pub layers: Vec<PacketLayer>,
    pub hex_dump: String,
    pub summary: String,
}

#[derive(Debug, Clone)]
pub struct PacketLayer {
    pub name: String,
    pub fields: Vec<(String, String)>,
}