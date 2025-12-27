use crate::net::{
    Network, Packet,
    scanner::{NetworkScanner, ScannerConfig},
};
use crate::types::{NetworkInterface, NetworkPacket, PacketDetail, PacketLayer, Protocol};
use ratatui::widgets::{ListState, TableState};
use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UIFocus {
    Interfaces,
    Packets,
    Details,
    Hex,
}

pub struct App {
    pub should_quit: bool,
    pub ui_focus: UIFocus,
    pub capture_active: Arc<AtomicBool>,
    pub interfaces: Vec<NetworkInterface>,
    pub packets: Arc<RwLock<Vec<NetworkPacket>>>,
    pub selected_packet: Option<usize>,
    pub packet_detail: Option<PacketDetail>,
    pub interfaces_list_state: ListState,
    pub packets_table_state: TableState,
    pub details_list_state: ListState,
    pub hex_list_state: ListState,
    pub selected_interface: usize,
    pub selected_detail_layer: Option<usize>,
    pub selected_hex_line: Option<usize>,
    pub start_time: Instant,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub packet_counter: u64,
    pub last_interface_change: Instant,
    pub interface_change_delay: Duration,
    pub network_scanner: Option<NetworkScanner>,
    pub network: Network,
    pub interface_changed: bool,
}

impl App {
    pub fn new() -> Self {
        let mut interfaces_list_state = ListState::default();
        interfaces_list_state.select(Some(0));
        let mut details_list_state = ListState::default();
        details_list_state.select(Some(0));
        let mut hex_list_state = ListState::default();
        hex_list_state.select(Some(0));
        let mut network = Network::new();
        network.scan_interfaces();
        let interfaces = Self::get_real_interfaces(&network);
        Self {
            should_quit: false,
            ui_focus: UIFocus::Packets,
            capture_active: Arc::new(AtomicBool::new(false)),
            interfaces: interfaces,
            packets: Arc::new(RwLock::new(Vec::new())),
            selected_packet: None,
            packet_detail: None,
            interfaces_list_state,
            packets_table_state: TableState::default(),
            details_list_state,
            hex_list_state,
            selected_interface: 0,
            selected_detail_layer: None,
            selected_hex_line: None,
            start_time: Instant::now(),
            total_packets: 0,
            total_bytes: 0,
            packet_counter: 0,
            last_interface_change: Instant::now(),
            interface_change_delay: Duration::from_millis(200),
            network_scanner: None,
            network,
            interface_changed: false,
        }
    }

    fn get_real_interfaces(network: &Network) -> Vec<NetworkInterface> {
        let interfaces = network.get_interfaces();
        interfaces
            .iter()
            .enumerate()
            .map(|(i, iface)| NetworkInterface {
                name: iface.display_name.clone(),
                description: iface.description.clone(),
                ip_address: iface.ip_address.clone(),
                mac_address: iface.mac_address.clone(),
                is_up: iface.is_up,
                packets_received: iface.packets_received,
                packets_sent: iface.packets_sent,
                bytes_received: iface.bytes_received,
                bytes_sent: iface.bytes_sent,
            })
            .collect()
    }

    pub fn start_real_capture(&mut self) {
        self.capture_active.store(true, Ordering::SeqCst);
        if self.interfaces.is_empty() {
            return;
        }
        let selected_iface_idx = self.selected_interface % self.interfaces.len();
        let selected_iface = &self.interfaces[selected_iface_idx];
        let config = ScannerConfig {
            filter_protocol: None,
        };
        let mut scanner = NetworkScanner::new(self.network.clone(), config);
        let (tx, rx) = std::sync::mpsc::channel::<Packet>();
        let packets_clone = self.packets.clone();
        let interface_name = selected_iface.name.clone();
        let capture_active_clone = self.capture_active.clone();
        let processing_thread = thread::spawn(move || {
            while let Ok(packet) = rx.recv() {
                if !capture_active_clone.load(Ordering::SeqCst) {
                    continue;
                }
                let mut packets_write = packets_clone.write().unwrap();
                let (src_port, dst_port) = Self::parse_ports_from_info(&packet.info);
                let network_packet = NetworkPacket {
                    id: packets_write.len() as u64,
                    timestamp: packet.timestamp.clone(),
                    source: packet.source,
                    destination: packet.destination,
                    src_port,
                    dst_port,
                    protocol: packet.protocol.clone(),
                    length: packet.length,
                    info: packet.info.clone(),
                    raw_data: packet.raw_data.clone(),
                };
                packets_write.push(network_packet);
                if packets_write.len() > 1000 {
                    let to_remove = packets_write.len() - 1000;
                    packets_write.drain(0..to_remove);
                }
            }
        });
        let scanner_thread = thread::spawn(move || {
            match scanner.start_scan(interface_name, move |packet| {
                let _ = tx.send(packet);
            }) {
                Ok(_) => loop {
                    std::thread::sleep(Duration::from_secs(1));
                },
                Err(e) => {}
            }
        });
    }

    fn parse_ports_from_info(info: &str) -> (u16, u16) {
        let mut src_port = 0;
        let mut dst_port = 0;
        if let Some(tcp_udp_pos) = info.find("TCP") {
            let rest = &info[tcp_udp_pos..];
            if let Some(src_pos) = rest.find(':') {
                if let Some(dst_pos) = rest[src_pos..].find("->") {
                    let src_str = &rest[src_pos + 1..src_pos + dst_pos];
                    if let Ok(port) = src_str.split(':').next().unwrap_or("0").parse::<u16>() {
                        src_port = port;
                    }
                    let dst_rest = &rest[src_pos + dst_pos + 2..];
                    if let Some(dst_colon_pos) = dst_rest.find(':') {
                        let dst_str = &dst_rest[dst_colon_pos + 1..];
                        if let Ok(port) = dst_str
                            .split_whitespace()
                            .next()
                            .unwrap_or("0")
                            .parse::<u16>()
                        {
                            dst_port = port;
                        }
                    }
                }
            }
        }
        (src_port, dst_port)
    }

    pub fn get_packets_read(&self) -> std::sync::RwLockReadGuard<'_, Vec<NetworkPacket>> {
        self.packets.read().unwrap()
    }

    pub fn get_packet(&self, index: usize) -> Option<NetworkPacket> {
        let packets_read = self.packets.read().unwrap();
        packets_read.get(index).cloned()
    }

    pub fn clear_packets(&mut self) {
        let mut packets_write = self.packets.write().unwrap();
        packets_write.clear();
        self.total_packets = 0;
        self.total_bytes = 0;
        self.packet_counter = 0;
        self.selected_packet = None;
        self.packet_detail = None;
        drop(packets_write);
    }

    pub fn focus_next(&mut self) {
        self.ui_focus = match self.ui_focus {
            UIFocus::Interfaces => UIFocus::Packets,
            UIFocus::Packets => UIFocus::Details,
            UIFocus::Details => UIFocus::Hex,
            UIFocus::Hex => UIFocus::Interfaces,
        };
    }

    pub fn interface_up(&mut self) {
        if self.ui_focus != UIFocus::Interfaces {
            return;
        }
        let old_interface = self.selected_interface;
        let i = match self.interfaces_list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.interfaces.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.interfaces_list_state.select(Some(i));
        self.selected_interface = i;
        self.interface_changed = old_interface != i;
    }

    pub fn interface_down(&mut self) {
        if self.ui_focus != UIFocus::Interfaces {
            return;
        }
        let old_interface = self.selected_interface;
        let i = match self.interfaces_list_state.selected() {
            Some(i) => {
                if i >= self.interfaces.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.interfaces_list_state.select(Some(i));
        self.selected_interface = i;
        self.interface_changed = old_interface != i; 
    }

    pub fn select_next_packet(&mut self) {
        if self.ui_focus != UIFocus::Packets {
            return;
        }
        let packets_read = self.packets.read().unwrap();
        let packet_count = packets_read.len();
        let i = match self.packets_table_state.selected() {
            Some(i) => {
                if i >= packet_count.saturating_sub(1) {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        drop(packets_read);
        self.packets_table_state.select(Some(i));
        self.selected_packet = Some(i);
        self.update_packet_detail(i);
    }

    pub fn select_prev_packet(&mut self) {
        if self.ui_focus != UIFocus::Packets {
            return;
        }
        let packets_read = self.packets.read().unwrap();
        let packet_count = packets_read.len();
        let i = match self.packets_table_state.selected() {
            Some(i) => {
                if i == 0 {
                    packet_count.saturating_sub(1)
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        drop(packets_read);
        self.packets_table_state.select(Some(i));
        self.selected_packet = Some(i);
        self.update_packet_detail(i);
    }

    pub fn detail_up(&mut self) {
        if self.ui_focus != UIFocus::Details {
            return;
        }
        if let Some(detail) = &self.packet_detail {
            let i = match self.details_list_state.selected() {
                Some(i) => {
                    if i == 0 {
                        detail.layers.len() - 1
                    } else {
                        i - 1
                    }
                }
                None => 0,
            };
            self.details_list_state.select(Some(i));
            self.selected_detail_layer = Some(i);
        }
    }

    pub fn detail_down(&mut self) {
        if self.ui_focus != UIFocus::Details {
            return;
        }
        if let Some(detail) = &self.packet_detail {
            let i = match self.details_list_state.selected() {
                Some(i) => {
                    if i >= detail.layers.len() - 1 {
                        0
                    } else {
                        i + 1
                    }
                }
                None => 0,
            };
            self.details_list_state.select(Some(i));
            self.selected_detail_layer = Some(i);
        }
    }

    pub fn hex_up(&mut self) {
        if self.ui_focus != UIFocus::Hex {
            return;
        }
        if let Some(detail) = &self.packet_detail {
            let line_count = detail.hex_dump.lines().count();
            let i = match self.hex_list_state.selected() {
                Some(i) => {
                    if i == 0 {
                        line_count - 1
                    } else {
                        i - 1
                    }
                }
                None => 0,
            };
            self.hex_list_state.select(Some(i));
            self.selected_hex_line = Some(i);
        }
    }

    pub fn hex_down(&mut self) {
        if self.ui_focus != UIFocus::Hex {
            return;
        }
        if let Some(detail) = &self.packet_detail {
            let line_count = detail.hex_dump.lines().count();
            let i = match self.hex_list_state.selected() {
                Some(i) => {
                    if i >= line_count - 1 {
                        0
                    } else {
                        i + 1
                    }
                }
                None => 0,
            };
            self.hex_list_state.select(Some(i));
            self.selected_hex_line = Some(i);
        }
    }

    fn update_packet_detail(&mut self, index: usize) {
        let packet_option = self.get_packet(index);
        if let Some(packet) = packet_option {
            let mut layers = Vec::new();
            layers.push(PacketLayer {
                name: "Ethernet Layer".to_string(),
                fields: vec![
                    ("Source MAC".to_string(), "00:1A:2B:3C:4D:5E".to_string()),
                    (
                        "Destination MAC".to_string(),
                        "AA:BB:CC:DD:EE:FF".to_string(),
                    ),
                    ("Type".to_string(), "0x0800 (IPv4)".to_string()),
                    ("Length".to_string(), "1500".to_string()),
                ],
            });
            layers.push(PacketLayer {
                name: "IP Layer".to_string(),
                fields: vec![
                    (
                        "Version".to_string(),
                        if packet.source.is_ipv6() {
                            "IPv6"
                        } else {
                            "IPv4"
                        }
                        .to_string(),
                    ),
                    ("Source Address".to_string(), packet.source.to_string()),
                    (
                        "Destination Address".to_string(),
                        packet.destination.to_string(),
                    ),
                    ("TTL".to_string(), "64".to_string()),
                    (
                        "Protocol".to_string(),
                        match &packet.protocol {
                            Protocol::TCP => "6 (TCP)",
                            Protocol::UDP => "17 (UDP)",
                            Protocol::ICMP => "1 (ICMP)",
                            _ => "Other",
                        }
                        .to_string(),
                    ),
                    ("Header Length".to_string(), "20 bytes".to_string()),
                ],
            });
            let transport_layer = match &packet.protocol {
                Protocol::TCP => PacketLayer {
                    name: "TCP Layer".to_string(),
                    fields: vec![
                        ("Source Port".to_string(), packet.src_port.to_string()),
                        ("Destination Port".to_string(), packet.dst_port.to_string()),
                        ("Sequence Number".to_string(), "123456789".to_string()),
                        ("Acknowledgment Number".to_string(), "987654321".to_string()),
                        ("Flags".to_string(), "ACK".to_string()),
                        ("Window Size".to_string(), "65535".to_string()),
                        ("Checksum".to_string(), "0xABCD".to_string()),
                        ("Urgent Pointer".to_string(), "0".to_string()),
                    ],
                },
                Protocol::UDP => PacketLayer {
                    name: "UDP Layer".to_string(),
                    fields: vec![
                        ("Source Port".to_string(), packet.src_port.to_string()),
                        ("Destination Port".to_string(), packet.dst_port.to_string()),
                        ("Length".to_string(), packet.length.to_string()),
                        ("Checksum".to_string(), "0xABCD".to_string()),
                    ],
                },
                _ => PacketLayer {
                    name: "Transport Layer".to_string(),
                    fields: vec![
                        ("Protocol".to_string(), format!("{:?}", packet.protocol)),
                        ("Length".to_string(), packet.length.to_string()),
                    ],
                },
            };
            layers.push(transport_layer);
            if packet.info.contains("HTTP") {
                layers.push(PacketLayer {
                    name: "HTTP Layer".to_string(),
                    fields: vec![
                        (
                            "Method".to_string(),
                            if packet.info.contains("GET") {
                                "GET"
                            } else {
                                "POST"
                            }
                            .to_string(),
                        ),
                        ("URL".to_string(), "/api/data".to_string()),
                        ("Version".to_string(), "HTTP/1.1".to_string()),
                        ("Host".to_string(), "example.com".to_string()),
                        ("User-Agent".to_string(), "xnet/0.1.0".to_string()),
                        ("Content-Type".to_string(), "application/json".to_string()),
                    ],
                });
            } else if packet.info.contains("DNS") {
                layers.push(PacketLayer {
                    name: "DNS Layer".to_string(),
                    fields: vec![
                        ("Query".to_string(), "google.com".to_string()),
                        ("Type".to_string(), "A".to_string()),
                        ("Class".to_string(), "IN".to_string()),
                        ("ID".to_string(), "0x1234".to_string()),
                        ("Flags".to_string(), "Standard Query".to_string()),
                    ],
                });
            }
            let hex_dump = "\
0000: 00 1A 2B 3C 4D 5E AA BB  CC DD EE FF 08 00 45 00  ..+<M^......E.
0010: 00 3C 12 34 40 00 40 06  8A BC C0 A8 01 64 08 08  .<.4@.@......d..
0020: 08 08 9C 40 00 50 12 34  56 78 00 00 00 00 50 02  ...@.P.Vx....P.
0030: 20 00 91 7C 00 00 47 45  54 20 2F 20 48 54 54 50   ..|..GET / HTTP
0040: 2F 31 2E 31 0D 0A 48 6F  73 74 3A 20 65 78 61 6D  /1.1..Host: exam
0050: 70 6C 65 2E 63 6F 6D 0D  0A 55 73 65 72 2D 41 67  ple.com..User-Ag
0060: 65 6E 74 3A 20 78 6E 65  74 2F 30 2E 31 2E 30 0D  ent: xnet/0.1.0"
                .to_string();
            self.packet_detail = Some(PacketDetail {
                layers,
                hex_dump,
                summary: format!(
                    "{}:{} → {}:{} ({})",
                    packet.source,
                    packet.src_port,
                    packet.destination,
                    packet.dst_port,
                    packet.info
                ),
            });
            self.details_list_state.select(Some(0));
            self.selected_detail_layer = Some(0);
            self.hex_list_state.select(Some(0));
            self.selected_hex_line = Some(0);
        }
    }

    pub fn stop_real_capture(&mut self) {
        self.capture_active.store(false, Ordering::SeqCst);
    }

    pub fn toggle_capture(&mut self) {
        if self.ui_focus == UIFocus::Interfaces && self.interface_changed {
            let was_capturing = self.capture_active.load(Ordering::SeqCst);
            if was_capturing {
                self.stop_real_capture();
            }
            self.clear_packets();
            self.interface_changed = false;
            if was_capturing {
                std::thread::sleep(Duration::from_millis(50));
                self.start_real_capture();
            } else {
                self.start_real_capture();
            }
        } else {
            if self.capture_active.load(Ordering::SeqCst) {
                self.stop_real_capture();
            } else {
                self.start_real_capture();
            }
        }
    }

    pub fn refresh_interfaces(&mut self) {
        self.network.scan_interfaces();
        self.interfaces = Self::get_real_interfaces(&self.network);
    }
}
