pub mod scanner;

use std::net::IpAddr;

use crate::types::Protocol;

#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    pub display_name: String,
    pub original_name: String,
    pub pnet_name: String,
    pub description: String,
    pub ip_address: String,
    pub mac_address: String,
    pub is_up: bool,
    pub packets_received: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub bytes_sent: u64,
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub timestamp: String,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: Protocol,
    pub length: usize,
    pub info: String,
    pub raw_data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PacketLayer {
    pub name: String,
    pub fields: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct PacketDetail {
    pub layers: Vec<PacketLayer>,
    pub hex_dump: String,
}

#[derive(Debug, Clone)]
pub struct Network {
    interfaces: Vec<InterfaceInfo>,
}

impl Network {
    pub fn new() -> Self {
        Self {
            interfaces: Vec::new(),
        }
    }

    pub fn scan_interfaces(&mut self) {
        self.interfaces.clear();
        let netdev_interfaces = netdev::get_interfaces();
        let pnet_interfaces = pnet::datalink::interfaces();
        for netdev_iface in netdev_interfaces {
            let ip_address = netdev_iface
                .ipv4
                .iter()
                .map(|ip| ip.to_string())
                .next()
                .unwrap_or_else(|| "N/A".to_string());
            let mac_address = netdev_iface
                .mac_addr
                .map(|mac| mac.to_string())
                .unwrap_or_else(|| "N/A".to_string());
            let friendly_name = netdev_iface
                .friendly_name
                .clone()
                .unwrap_or(netdev_iface.name.clone());
            let is_up = netdev_iface.is_up();
            let pnet_name = pnet_interfaces
                .iter()
                .find(|pnet_iface| {
                    let netdev_desc = netdev_iface.description.as_deref().unwrap_or("");
                    !netdev_desc.is_empty() && pnet_iface.description == netdev_desc
                })
                .map(|pnet_iface| pnet_iface.name.clone())
                .unwrap_or_else(|| "N/A".to_string());
            let interface_info = InterfaceInfo {
                display_name: friendly_name,
                original_name: netdev_iface.name.clone(),
                pnet_name,
                description: netdev_iface.description.clone().unwrap_or_default(),
                ip_address,
                mac_address,
                is_up,
                packets_received: 0,
                bytes_received: 0,
                packets_sent: 0,
                bytes_sent: 0,
            };
            self.interfaces.push(interface_info);
        }
    }

    pub fn get_interfaces(&self) -> &[InterfaceInfo] {
        &self.interfaces
    }

    pub fn find_interface_by_name(&self, name: &str) -> Option<usize> {
        self.interfaces
            .iter()
            .position(|iface| iface.display_name == name)
    }

    pub fn find_interface_by_name_or_guid(&self, name: &str) -> Option<usize> {
        self.interfaces
            .iter()
            .position(|iface| iface.display_name == name || iface.display_name.contains(name))
    }
}

pub fn parse_ethernet_frame(frame: &[u8]) -> Option<Packet> {
    if frame.len() < 14 {
        return None;
    }
    let dest_mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]
    );
    let src_mac = format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]
    );
    let ether_type = ((frame[12] as u16) << 8) | frame[13] as u16;
    let protocol = match ether_type {
        0x0800 => Protocol::IP,
        0x0806 => Protocol::ARP,
        0x86DD => Protocol::IPv6,
        _ => Protocol::Other(format!("0x{:04x}", ether_type)),
    };
    let packet = Packet {
        timestamp: chrono::Local::now().format("%H:%M:%S%.3f").to_string(),
        source: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        destination: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
        protocol,
        length: frame.len(),
        info: format!("Ethernet: {} -> {}", src_mac, dest_mac),
        raw_data: frame.to_vec(),
    };
    Some(packet)
}

pub fn generate_hex_dump(data: &[u8], bytes_per_line: usize) -> String {
    let mut result = String::new();
    for (i, chunk) in data.chunks(bytes_per_line).enumerate() {
        result.push_str(&format!("{:04x}: ", i * bytes_per_line));
        for (j, byte) in chunk.iter().enumerate() {
            result.push_str(&format!("{:02x}", byte));
            if j % 2 == 1 && j < chunk.len() - 1 {
                result.push(' ');
            }
        }
        for pos in chunk.len()..bytes_per_line {
            result.push_str("  ");
            if (chunk.len() + pos) % 2 == 1 {
                result.push(' ');
            }
        }
        result.push_str("  ");
        for byte in chunk {
            let c = *byte as char;
            if c.is_ascii_graphic() || c == ' ' {
                result.push(c);
            } else {
                result.push('.');
            }
        }
        result.push('\n');
    }
    result
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::net::{
        Network,
        scanner::{NetworkScanner, ScannerConfig},
    };

    #[test]
    fn test_realtime_packet_capture_table_format() {
        use std::time::{Duration, Instant};
        println!("=== Real-time Packet Capture Table Format Test ===");
        let mut network = Network::new();
        network.scan_interfaces();
        let interfaces = network.get_interfaces();
        if interfaces.is_empty() {
            println!("No network interfaces found. Test skipped.");
            return;
        }
        let active_iface = interfaces
            .iter()
            .find(|iface| iface.is_up && iface.ip_address != "N/A");
        if let Some(iface) = active_iface {
            println!(
                "Using interface: {} (IP: {})",
                iface.display_name, iface.ip_address
            );
            let config = crate::net::scanner::ScannerConfig {
                filter_protocol: None,
            };
            let mut scanner = crate::net::scanner::NetworkScanner::new(network.clone(), config);
            let captured_packets = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let captured_packets_clone = captured_packets.clone();
            match scanner.start_scan(iface.display_name.clone(), move |packet| {
                let mut packets = captured_packets_clone.lock().unwrap();
                packets.push(packet);
            }) {
                Ok(_) => {
                    println!("Starting packet capture for 5 seconds...");
                    println!("Press Ctrl+C or wait for timeout");
                    println!();
                    let start_time = Instant::now();
                    let mut last_packet_count = 0;
                    while start_time.elapsed() < Duration::from_secs(5) {
                        let packets = captured_packets.lock().unwrap();
                        let packet_count = packets.len();
                        if packet_count > last_packet_count {
                            println!("=== New Packet(s) Captured ===");
                            println!(
                                "Time         Source              Destination         Protocol  Length  Info"
                            );
                            println!(
                                "-------------------------------------------------------------------------------"
                            );
                            for i in last_packet_count..packet_count {
                                let packet = &packets[i];
                                let protocol_str = match &packet.protocol {
                                    crate::types::Protocol::TCP => "TCP",
                                    crate::types::Protocol::UDP => "UDP",
                                    crate::types::Protocol::HTTP => "HTTP",
                                    crate::types::Protocol::HTTPS => "HTTPS",
                                    crate::types::Protocol::DNS => "DNS",
                                    crate::types::Protocol::ICMP => "ICMP",
                                    crate::types::Protocol::ARP => "ARP",
                                    crate::types::Protocol::IP => "IP",
                                    crate::types::Protocol::IPv6 => "IPv6",
                                    crate::types::Protocol::Other(s) => s.as_str(),
                                };
                                println!(
                                    "{:<12} {:<20} {:<20} {:<9} {:<7} {}",
                                    packet.timestamp.chars().take(12).collect::<String>(),
                                    format!("{}", packet.source)
                                        .chars()
                                        .take(20)
                                        .collect::<String>(),
                                    format!("{}", packet.destination)
                                        .chars()
                                        .take(20)
                                        .collect::<String>(),
                                    protocol_str,
                                    packet.length,
                                    packet.info.chars().take(40).collect::<String>()
                                );
                            }

                            let total_bytes: usize = packets.iter().map(|p| p.length).sum();
                            println!(
                                "-------------------------------------------------------------------------------"
                            );
                            println!(
                                "Total: {} packets | {} B | Live Capture",
                                packet_count, total_bytes
                            );
                            println!();
                            last_packet_count = packet_count;
                        }
                        drop(packets);
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    scanner.stop_scan();
                    let final_packets = captured_packets.lock().unwrap();
                    println!("=== Capture Complete ===");
                    println!("Total packets captured: {}", final_packets.len());
                    if std::env::var("CI").is_err() {
                        assert!(
                            final_packets.len() > 0,
                            "No packets captured in non-CI environment"
                        );
                    } else {
                        println!("CI environment detected, skipping packet count assertion");
                    }
                }
                Err(e) => {
                    println!("Failed to start capture: {}", e);
                    println!("Test skipped.");
                }
            }
        } else {
            println!("No active network interface found. Test skipped.");
        }
        println!("=== Test completed ===");
    }

    #[test]
    fn test_packet_table_format_output() {
        use crate::net::{Packet, Protocol};
        use std::net::IpAddr;
        let test_packets = vec![
            Packet {
                timestamp: "12:34:56.789".to_string(),
                source: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)),
                destination: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
                protocol: Protocol::TCP,
                length: 64,
                info: "TCP 192.168.1.100:8080 -> 192.168.1.1:443 [SYN, ACK] Len=32".to_string(),
                raw_data: vec![0u8; 64],
            },
            Packet {
                timestamp: "12:34:56.890".to_string(),
                source: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
                destination: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)),
                protocol: Protocol::UDP,
                length: 128,
                info: "UDP 192.168.1.1:53 -> 192.168.1.100:5353 Len=96".to_string(),
                raw_data: vec![0u8; 128],
            },
            Packet {
                timestamp: "12:34:57.123".to_string(),
                source: IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                destination: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100)),
                protocol: Protocol::DNS,
                length: 92,
                info: "DNS Response".to_string(),
                raw_data: vec![0u8; 92],
            },
        ];
        println!("\n=== Packet Table Format Output ===");
        println!("Time         Source              Destination         Protocol  Length  Info");
        println!("-------------------------------------------------------------------------------");
        for packet in test_packets.clone() {
            let protocol_str = match &packet.protocol {
                Protocol::TCP => "TCP",
                Protocol::UDP => "UDP",
                Protocol::HTTP => "HTTP",
                Protocol::HTTPS => "HTTPS",
                Protocol::DNS => "DNS",
                Protocol::ICMP => "ICMP",
                Protocol::ARP => "ARP",
                Protocol::IP => "IP",
                Protocol::IPv6 => "IPv6",
                Protocol::Other(s) => s.as_str(),
            };
            println!(
                "{:<12} {:<20} {:<20} {:<9} {:<7} {}",
                packet.timestamp,
                packet.source.to_string(),
                packet.destination.to_string(),
                protocol_str,
                packet.length,
                packet.info
            );
        }
        println!("-------------------------------------------------------------------------------");
        println!(
            "Total: {} packets | {} B | Selected: None",
            test_packets.len(),
            test_packets.iter().map(|p| p.length).sum::<usize>()
        );
        assert_eq!(test_packets.len(), 3);
        for packet in &test_packets {
            let row_format = format!(
                "{} {} {} {} {} {}",
                packet.timestamp,
                packet.source,
                packet.destination,
                match &packet.protocol {
                    Protocol::TCP => "TCP",
                    Protocol::UDP => "UDP",
                    Protocol::DNS => "DNS",
                    _ => "Other",
                },
                packet.length,
                packet.info
            );
            assert!(!row_format.is_empty());
        }
        println!("=== Test completed successfully ===");
    }

    #[test]
    fn test_network_scanner_with_pnet_name() {
        use std::time::Duration;
        println!("Testing network scanner (using pnet interface name)...");
        let mut network = Network::new();
        network.scan_interfaces();
        let interfaces = network.get_interfaces();
        println!("Found {} network cards", interfaces.len());
        let ethernet_iface = interfaces
            .iter()
            .find(|iface| iface.display_name.contains("以太网"));
        if let Some(ethernet_iface) = ethernet_iface {
            println!("\nFound Ethernet interface:");
            println!("  Friendly name: {}", ethernet_iface.display_name);
            println!("  Original name: {}", ethernet_iface.original_name);
            println!("  Pnet name: {}", ethernet_iface.pnet_name);
            println!("  IP: {}", ethernet_iface.ip_address);
            if ethernet_iface.pnet_name != "N/A" {
                let config = ScannerConfig {
                    filter_protocol: None,
                };
                let mut packet_scanner = NetworkScanner::new(network.clone(), config);
                println!("\nStarting packet capture test...");
                let captured_packets = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                let captured_packets_clone = captured_packets.clone();
                match packet_scanner.start_scan(
                    ethernet_iface.display_name.clone(),
                    move |packet| {
                        let mut packets = captured_packets_clone.lock().unwrap();
                        packets.push(packet);
                    },
                ) {
                    Ok(_) => {
                        std::thread::sleep(Duration::from_secs(1));
                        packet_scanner.stop_scan();
                        let packets = captured_packets.lock().unwrap();
                        println!("Captured {} packets", packets.len());
                        if !packets.is_empty() {
                            let packet = &packets[0];
                            println!("First packet info:");
                            println!("  Time: {}", packet.timestamp);
                            println!(
                                "  Source: {} -> Destination: {}",
                                packet.source, packet.destination
                            );
                            println!("  Protocol: {:?}", packet.protocol);
                            println!("  Length: {} bytes", packet.length);
                            println!("  Info: {}", packet.info);
                        }
                    }
                    Err(e) => {
                        println!("Packet capture failed: {}", e);
                    }
                }
            } else {
                println!("No corresponding pnet interface name found");
            }
        } else {
            println!("No Ethernet interface found");
        }
        println!("\nTest completed");
    }

    #[test]
    fn test_netdev_interfaces() {
        eprintln!("Using netdev to get network card list...");
        let interfaces = netdev::get_interfaces();
        for iface in &interfaces {
            println!(
                "Interface: {} (GUID: {}), IPs: {:?}, Status: {}",
                iface
                    .friendly_name
                    .clone()
                    .unwrap_or("No friendly name".to_string()),
                iface.name,
                iface.ipv4,
                if iface.is_up() { "Enabled" } else { "Disabled" }
            );
        }
        if let Some(eth_iface) = interfaces.iter().find(|i| {
            i.is_up()
                && !i.is_loopback()
                && i.friendly_name
                    .as_ref()
                    .map_or(false, |name| name.contains("Ethernet"))
        }) {
            println!(
                "\nFound Ethernet interface: {} (GUID: {})",
                eth_iface.friendly_name.as_ref().unwrap(),
                eth_iface.name
            );
        }
        eprintln!("(Need to add netdev dependency first)");
    }

    #[test]
    fn test_pnet_interface_names() {
        println!("=== Viewing pnet recognizable interface names ===");
        let interfaces = pnet::datalink::interfaces();
        for (i, iface) in interfaces.iter().enumerate() {
            println!("\n{}. Interface information:", i + 1);
            println!("   Name: '{}'", iface.name);
            println!("   Description: '{}'", iface.description);
            println!("   Index: {}", iface.index);
            println!("   MAC: {:?}", iface.mac);
            println!("   IP addresses: {:?}", iface.ips);
            println!(
                "   Status: {}",
                if iface.is_up() { "Enabled" } else { "Disabled" }
            );
            println!(
                "   Is loopback: {}",
                if iface.is_loopback() { "Yes" } else { "No" }
            );

            println!("   Testing packet capture channel...");
            match pnet::datalink::channel(iface, Default::default()) {
                Ok(pnet::datalink::Channel::Ethernet(_, _)) => {
                    println!("   ✓ Supports Ethernet packet capture");
                }
                Ok(_) => println!("   ✗ Does not support Ethernet packet capture"),
                Err(e) => println!("   ✗ Error: {}", e),
            }
        }
        println!("\n=== Test completed ===");
        println!("\n=== Summary ===");
        println!("The interface name pnet needs to use is the 'Name' field shown above");
        println!("On Windows it's usually in the format: \\Device\\NPF_GUID");
        println!("The correct name for your 'Ethernet' interface might be:");
        for iface in interfaces {
            if iface.description.contains("Realtek Gaming") || iface.description.contains("Realtek")
            {
                println!("  '{}' - {}", iface.name, iface.description);
            }
        }
    }
}
