use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use pnet::packet::Packet as PnetPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crate::net::{Network, Packet, PacketDetail, PacketLayer, Protocol};

#[derive(Debug, Clone)]
pub struct ScannerConfig {
    pub filter_protocol: Option<Protocol>,
}

pub struct NetworkScanner {
    config: ScannerConfig,
    is_running: bool,
    packets: Vec<Packet>,
    pub network: Network,
    current_interface_name: Option<String>,
}

impl NetworkScanner {
    pub fn new(network: Network, config: ScannerConfig) -> Self {
        NetworkScanner {
            config,
            is_running: false,
            packets: Vec::new(),
            network,
            current_interface_name: None,
        }
    }

    pub fn start_scan<F>(&mut self, interface_name: String, mut callback: F) -> Result<(), String>
    where
        F: FnMut(Packet) + Send + 'static,
    {
        if self.is_running {
            return Err("Scanner is already running".to_string());
        }
        let interface_index = self
            .network
            .find_interface_by_name(&interface_name)
            .or_else(|| self.network.find_interface_by_name_or_guid(&interface_name))
            .ok_or_else(|| format!("Interface '{}' not found", interface_name))?;
        let interfaces = self.network.get_interfaces();
        let interface_info = &interfaces[interface_index];
        if interface_info.pnet_name == "N/A" {
            return Err(format!(
                "Interface '{}' has no valid pnet name",
                interface_name
            ));
        }
        let pnet_interfaces = pnet::datalink::interfaces();
        let pnet_interface = pnet_interfaces
            .iter()
            .find(|iface| iface.name == interface_info.pnet_name)
            .ok_or_else(|| format!("Pnet interface '{}' not found", interface_info.pnet_name))?;
        self.current_interface_name = Some(interface_name);
        self.is_running = true;
        let config = self.config.clone();
        let interface = pnet_interface.clone();
        thread::spawn(move || {
            let (mut sender, mut receiver) = match datalink::channel(&interface, Default::default())
            {
                Ok(Ethernet(tx, rx)) => (tx, rx),
                Ok(_) => {
                    return;
                }
                Err(e) => {
                    return;
                }
            };
            loop {
                match receiver.next() {
                    Ok(packet_data) => {
                        if let Some(parsed_packet) = Self::parse_packet(&packet_data) {
                            if let Some(filter) = &config.filter_protocol {
                                if !Self::matches_protocol(&parsed_packet.protocol, filter) {
                                    continue;
                                }
                            }
                            callback(parsed_packet);
                        }
                    }
                    Err(e) => {
                        thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        });
        let (tx, rx) = std::sync::mpsc::channel();
        let config_clone = self.config.clone();
        let interface_clone = pnet_interface.clone();
        thread::spawn(
            move || {
                if let Err(e) = Self::capture_packets(&interface_clone, tx, config_clone) {}
            },
        );
        self.process_packets(rx);
        Ok(())
    }

    pub fn stop_scan(&mut self) {
        self.is_running = false;
        self.current_interface_name = None;
    }

    pub fn get_packets(&self) -> &[Packet] {
        &self.packets
    }

    pub fn clear_packets(&mut self) {
        self.packets.clear();
    }

    pub fn get_current_interface(&self) -> Option<&str> {
        self.current_interface_name.as_deref()
    }

    fn capture_packets(
        interface: &NetworkInterface,
        tx: Sender<Packet>,
        config: ScannerConfig,
    ) -> Result<(), String> {
        let (mut sender, mut receiver) = match datalink::channel(interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err("Unsupported channel type".to_string()),
            Err(e) => return Err(format!("Failed to create channel: {}", e)),
        };
        let start_time = Instant::now();
        let mut packet_count = 0;
        loop {
            match receiver.next() {
                Ok(packet) => {
                    if let Some(parsed_packet) = Self::parse_packet(&packet) {
                        if let Some(filter) = &config.filter_protocol {
                            if !Self::matches_protocol(&parsed_packet.protocol, filter) {
                                continue;
                            }
                        }
                        if tx.send(parsed_packet).is_err() {
                            break;
                        }
                        packet_count += 1;
                    }
                }
                Err(e) => {}
            }
        }
        Ok(())
    }

    fn parse_packet(ethernet_data: &[u8]) -> Option<Packet> {
        let ethernet = EthernetPacket::new(ethernet_data)?;
        let src_mac = ethernet.get_source();
        let dest_mac = ethernet.get_destination();
        let ether_type = ethernet.get_ethertype();
        let (protocol, source, destination, info) = match ether_type {
            EtherTypes::Ipv4 => {
                let ipv4 = Ipv4Packet::new(ethernet.payload())?;
                Self::parse_ipv4_packet(&ipv4, src_mac, dest_mac)
            }
            EtherTypes::Ipv6 => {
                let ipv6 = Ipv6Packet::new(ethernet.payload())?;
                Self::parse_ipv6_packet(&ipv6, src_mac, dest_mac)
            }
            EtherTypes::Arp => (
                Protocol::ARP,
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                format!("ARP: {} -> {}", src_mac, dest_mac),
            ),
            _ => (
                Protocol::Other(format!("0x{:04x}", ether_type.0)),
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                format!("Unknown: {} -> {}", src_mac, dest_mac),
            ),
        };
        Some(Packet {
            timestamp: chrono::Local::now().format("%H:%M:%S%.3f").to_string(),
            source,
            destination,
            protocol,
            length: ethernet_data.len(),
            info,
            raw_data: ethernet_data.to_vec(),
        })
    }

    fn parse_ipv4_packet(
        ipv4: &Ipv4Packet,
        src_mac: pnet::datalink::MacAddr,
        dest_mac: pnet::datalink::MacAddr,
    ) -> (Protocol, IpAddr, IpAddr, String) {
        let source = IpAddr::V4(ipv4.get_source());
        let destination = IpAddr::V4(ipv4.get_destination());
        let protocol = ipv4.get_next_level_protocol();
        let (proto, info) = match protocol {
            IpNextHeaderProtocols::Tcp => {
                if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                    let flags = Self::parse_tcp_flags(tcp.get_flags().into());
                    (
                        Protocol::TCP,
                        format!(
                            "TCP {}:{} -> {}:{} [{}] Len={}",
                            source,
                            tcp.get_source(),
                            destination,
                            tcp.get_destination(),
                            flags,
                            tcp.payload().len()
                        ),
                    )
                } else {
                    (Protocol::TCP, format!("TCP {} -> {}", source, destination))
                }
            }
            IpNextHeaderProtocols::Udp => {
                if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                    (
                        Protocol::UDP,
                        format!(
                            "UDP {}:{} -> {}:{} Len={}",
                            source,
                            udp.get_source(),
                            destination,
                            udp.get_destination(),
                            udp.get_length()
                        ),
                    )
                } else {
                    (Protocol::UDP, format!("UDP {} -> {}", source, destination))
                }
            }
            IpNextHeaderProtocols::Icmp => (
                Protocol::ICMP,
                format!("ICMP {} -> {}", source, destination),
            ),
            _ => (
                Protocol::Other(format!("IP Protocol {}", protocol.0)),
                format!("IP {} -> {}", source, destination),
            ),
        };
        (proto, source, destination, info)
    }

    fn parse_ipv6_packet(
        ipv6: &Ipv6Packet,
        src_mac: pnet::datalink::MacAddr,
        dest_mac: pnet::datalink::MacAddr,
    ) -> (Protocol, IpAddr, IpAddr, String) {
        let source = IpAddr::V6(ipv6.get_source());
        let destination = IpAddr::V6(ipv6.get_destination());
        let next_header = ipv6.get_next_header();
        let (proto, info) = match next_header {
            IpNextHeaderProtocols::Tcp => (
                Protocol::TCP,
                format!("IPv6 TCP {} -> {}", source, destination),
            ),
            IpNextHeaderProtocols::Udp => (
                Protocol::UDP,
                format!("IPv6 UDP {} -> {}", source, destination),
            ),
            _ => (
                Protocol::Other(format!("IPv6 Protocol {}", next_header.0)),
                format!("IPv6 {} -> {}", source, destination),
            ),
        };
        (proto, source, destination, info)
    }

    fn parse_tcp_flags(flags: u16) -> String {
        let mut flag_str = String::new();
        if flags & 0x01 != 0 {
            flag_str.push('F');
        }
        if flags & 0x02 != 0 {
            flag_str.push('S');
        }
        if flags & 0x04 != 0 {
            flag_str.push('R');
        }
        if flags & 0x08 != 0 {
            flag_str.push('P');
        }
        if flags & 0x10 != 0 {
            flag_str.push('A');
        }
        if flags & 0x20 != 0 {
            flag_str.push('U');
        }
        flag_str
    }

    fn matches_protocol(packet_proto: &Protocol, filter: &Protocol) -> bool {
        match (packet_proto, filter) {
            (Protocol::TCP, Protocol::TCP) => true,
            (Protocol::UDP, Protocol::UDP) => true,
            (Protocol::HTTP, Protocol::HTTP) => true,
            (Protocol::HTTPS, Protocol::HTTPS) => true,
            (Protocol::DNS, Protocol::DNS) => true,
            (Protocol::ICMP, Protocol::ICMP) => true,
            (Protocol::ARP, Protocol::ARP) => true,
            (Protocol::Other(_), Protocol::Other(_)) => true,
            _ => false,
        }
    }

    fn process_packets(&mut self, rx: Receiver<Packet>) {
        while self.is_running {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(packet) => {
                    self.packets.push(packet);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }
        }
    }

    pub fn generate_packet_detail(packet: &Packet) -> PacketDetail {
        let mut layers = Vec::new();
        if packet.raw_data.len() >= 14 {
            let ethernet_layer = Self::parse_ethernet_layer(&packet.raw_data[..14]);
            layers.push(ethernet_layer);
        }
        if packet.raw_data.len() > 14 {
            let ip_layer = Self::parse_ip_layer(&packet.raw_data[14..]);
            if let Some(layer) = ip_layer {
                layers.push(layer);
            }
        }
        if let Some(transport_layer) = Self::parse_transport_layer(packet) {
            layers.push(transport_layer);
        }
        if let Some(app_layer) = Self::parse_application_layer(packet) {
            layers.push(app_layer);
        }
        PacketDetail {
            layers,
            hex_dump: super::generate_hex_dump(&packet.raw_data, 16),
        }
    }

    fn parse_ethernet_layer(data: &[u8]) -> PacketLayer {
        let mut fields = Vec::new();
        if data.len() >= 12 {
            fields.push((
                "Destination MAC".to_string(),
                format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    data[0], data[1], data[2], data[3], data[4], data[5]
                ),
            ));
            fields.push((
                "Source MAC".to_string(),
                format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    data[6], data[7], data[8], data[9], data[10], data[11]
                ),
            ));
        }
        if data.len() >= 14 {
            let ether_type = ((data[12] as u16) << 8) | data[13] as u16;
            fields.push(("EtherType".to_string(), format!("0x{:04x}", ether_type)));
            let type_desc = match ether_type {
                0x0800 => "IPv4",
                0x0806 => "ARP",
                0x86DD => "IPv6",
                0x8100 => "VLAN",
                0x88CC => "LLDP",
                _ => "Unknown",
            };
            fields.push(("Type Description".to_string(), type_desc.to_string()));
        }
        PacketLayer {
            name: "Ethernet Frame".to_string(),
            fields,
        }
    }

    fn parse_ip_layer(data: &[u8]) -> Option<PacketLayer> {
        if data.len() < 20 {
            return None;
        }
        let version = data[0] >> 4;
        if version == 4 {
            let mut fields = Vec::new();
            fields.push(("Version".to_string(), "4".to_string()));
            fields.push((
                "Header Length".to_string(),
                format!("{} bytes", (data[0] & 0x0F) * 4),
            ));
            fields.push((
                "Differentiated Services".to_string(),
                format!("0x{:02x}", data[1]),
            ));
            fields.push((
                "Total Length".to_string(),
                format!("{}", ((data[2] as u16) << 8) | data[3] as u16),
            ));
            fields.push((
                "Identification".to_string(),
                format!("0x{:04x}", ((data[4] as u16) << 8) | data[5] as u16),
            ));
            let flags = data[6] >> 5;
            let fragment_offset = (((data[6] & 0x1F) as u16) << 8) | data[7] as u16;
            fields.push(("Flags".to_string(), format!("0x{:02x}", flags)));
            fields.push((
                "Fragment Offset".to_string(),
                format!("{}", fragment_offset),
            ));
            fields.push(("Time to Live".to_string(), format!("{}", data[8])));
            fields.push(("Protocol".to_string(), format!("{}", data[9])));
            fields.push((
                "Header Checksum".to_string(),
                format!("0x{:04x}", ((data[10] as u16) << 8) | data[11] as u16),
            ));
            fields.push((
                "Source IP".to_string(),
                format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]),
            ));
            fields.push((
                "Destination IP".to_string(),
                format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]),
            ));
            Some(PacketLayer {
                name: "IPv4 Packet".to_string(),
                fields,
            })
        } else if version == 6 {
            let mut fields = Vec::new();
            fields.push(("Version".to_string(), "6".to_string()));
            fields.push((
                "Traffic Class".to_string(),
                format!("0x{:02x}", (data[0] & 0x0F) << 4 | data[1] >> 4),
            ));
            fields.push((
                "Flow Label".to_string(),
                format!(
                    "0x{:05x}",
                    ((data[1] as u32 & 0x0F) << 16) | ((data[2] as u32) << 8) | data[3] as u32
                ),
            ));
            fields.push((
                "Payload Length".to_string(),
                format!("{}", ((data[4] as u16) << 8) | data[5] as u16),
            ));
            fields.push(("Next Header".to_string(), format!("{}", data[6])));
            fields.push(("Hop Limit".to_string(), format!("{}", data[7])));
            let src_ip = format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                data[8],
                data[9],
                data[10],
                data[11],
                data[12],
                data[13],
                data[14],
                data[15],
                data[16],
                data[17],
                data[18],
                data[19],
                data[20],
                data[21],
                data[22],
                data[23]
            );
            fields.push(("Source IP".to_string(), src_ip));
            let dst_ip = format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                data[24],
                data[25],
                data[26],
                data[27],
                data[28],
                data[29],
                data[30],
                data[31],
                data[32],
                data[33],
                data[34],
                data[35],
                data[36],
                data[37],
                data[38],
                data[39]
            );
            fields.push(("Destination IP".to_string(), dst_ip));
            Some(PacketLayer {
                name: "IPv6 Packet".to_string(),
                fields,
            })
        } else {
            None
        }
    }

    fn parse_transport_layer(packet: &Packet) -> Option<PacketLayer> {
        match &packet.protocol {
            Protocol::TCP => {
                let mut fields = Vec::new();
                fields.push(("Protocol".to_string(), "TCP".to_string()));
                fields.push(("Source".to_string(), packet.source.to_string()));
                fields.push(("Destination".to_string(), packet.destination.to_string()));
                fields.push(("Length".to_string(), packet.length.to_string()));
                Some(PacketLayer {
                    name: "TCP Segment".to_string(),
                    fields,
                })
            }
            Protocol::UDP => {
                let mut fields = Vec::new();
                fields.push(("Protocol".to_string(), "UDP".to_string()));
                fields.push(("Source".to_string(), packet.source.to_string()));
                fields.push(("Destination".to_string(), packet.destination.to_string()));
                fields.push(("Length".to_string(), packet.length.to_string()));
                Some(PacketLayer {
                    name: "UDP Datagram".to_string(),
                    fields,
                })
            }
            _ => None,
        }
    }

    fn parse_application_layer(packet: &Packet) -> Option<PacketLayer> {
        if packet.info.contains("HTTP") {
            let mut fields = Vec::new();
            fields.push(("Protocol".to_string(), "HTTP".to_string()));
            if let Some(first_line) = String::from_utf8_lossy(&packet.raw_data).lines().next() {
                if first_line.contains("GET")
                    || first_line.contains("POST")
                    || first_line.contains("PUT")
                    || first_line.contains("DELETE")
                {
                    fields.push((
                        "Method".to_string(),
                        first_line
                            .split_whitespace()
                            .next()
                            .unwrap_or("Unknown")
                            .to_string(),
                    ));
                }
            }
            Some(PacketLayer {
                name: "HTTP Message".to_string(),
                fields,
            })
        } else if packet.info.contains("DNS") {
            let mut fields = Vec::new();
            fields.push(("Protocol".to_string(), "DNS".to_string()));
            Some(PacketLayer {
                name: "DNS Message".to_string(),
                fields,
            })
        } else {
            None
        }
    }
}
