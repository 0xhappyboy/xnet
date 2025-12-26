use crate::types::{NetworkInterface, NetworkPacket, PacketDetail, PacketLayer, Protocol};
use ratatui::widgets::{ListState, TableState};
use std::{
    net::IpAddr,
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
    pub capture_active: bool,
    pub interfaces: Vec<NetworkInterface>,
    pub packets: Vec<NetworkPacket>,
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
}

impl App {
    pub fn new() -> Self {
        let mut interfaces_list_state = ListState::default();
        interfaces_list_state.select(Some(0));
        let mut details_list_state = ListState::default();
        details_list_state.select(Some(0));
        let mut hex_list_state = ListState::default();
        hex_list_state.select(Some(0));
        Self {
            should_quit: false,
            ui_focus: UIFocus::Packets,
            capture_active: false,
            interfaces: Self::generate_mock_interfaces(),
            packets: Vec::new(),
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
        }
    }

    fn generate_mock_interfaces() -> Vec<NetworkInterface> {
        vec![
            NetworkInterface {
                name: "eth0".to_string(),
                description: "Main Ethernet".to_string(),
                ip_address: "192.168.1.100".to_string(),
                mac_address: "00:1A:2B:3C:4D:5E".to_string(),
                is_up: true,
                packets_received: 15042,
                packets_sent: 8923,
                bytes_received: 15203456,
                bytes_sent: 8456723,
            },
            NetworkInterface {
                name: "wlan0".to_string(),
                description: "Wireless Network".to_string(),
                ip_address: "10.0.0.15".to_string(),
                mac_address: "AA:BB:CC:DD:EE:FF".to_string(),
                is_up: true,
                packets_received: 23456,
                packets_sent: 12345,
                bytes_received: 45678901,
                bytes_sent: 23456789,
            },
            NetworkInterface {
                name: "lo".to_string(),
                description: "Local Loopback".to_string(),
                ip_address: "127.0.0.1".to_string(),
                mac_address: "00:00:00:00:00:00".to_string(),
                is_up: true,
                packets_received: 500,
                packets_sent: 500,
                bytes_received: 50000,
                bytes_sent: 50000,
            },
            NetworkInterface {
                name: "docker0".to_string(),
                description: "Docker Bridge".to_string(),
                ip_address: "172.17.0.1".to_string(),
                mac_address: "02:42:AC:11:00:01".to_string(),
                is_up: true,
                packets_received: 7890,
                packets_sent: 4567,
                bytes_received: 12345678,
                bytes_sent: 8765432,
            },
        ]
    }

    pub fn generate_mock_packets(&mut self, count: usize) {
        use std::net::{Ipv4Addr, Ipv6Addr};
        let protocols = vec![
            Protocol::TCP,
            Protocol::UDP,
            Protocol::HTTP,
            Protocol::HTTPS,
            Protocol::DNS,
            Protocol::ICMP,
            Protocol::ARP,
        ];
        let infos = vec![
            "GET /api/data HTTP/1.1",
            "DNS query for google.com",
            "TCP SYN → 443",
            "TLS Client Hello",
            "ICMP Echo Request",
            "ARP Who has 192.168.1.1?",
            "POST /login HTTP/1.1",
            "UDP 53 → 53",
            "TCP ACK",
            "WebSocket Handshake",
        ];
        for _ in 0..count {
            self.packet_counter += 1;
            let protocol = protocols[self.packet_counter as usize % protocols.len()].clone();
            let info = infos[self.packet_counter as usize % infos.len()].to_string();
            let packet = NetworkPacket {
                id: self.packet_counter,
                timestamp: chrono::Local::now().format("%H:%M:%S%.3f").to_string(),
                source: if self.packet_counter % 3 == 0 {
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
                } else {
                    IpAddr::V4(Ipv4Addr::new(
                        192,
                        168,
                        1,
                        (self.packet_counter % 255) as u8,
                    ))
                },
                destination: if self.packet_counter % 4 == 0 {
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))
                } else {
                    IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
                },
                src_port: 40000 + (self.packet_counter % 1000) as u16,
                dst_port: match protocol {
                    Protocol::TCP => 8080,
                    Protocol::UDP => 53,
                    Protocol::HTTP => 80,
                    Protocol::HTTPS => 443,
                    Protocol::DNS => 53,
                    _ => 0,
                },
                protocol,
                length: 64 + (self.packet_counter % 1400) as usize,
                info: info.clone(),
                raw_data: vec![0u8; 32],
            };
            self.packets.push(packet.clone());
            self.total_packets += 1;
            self.total_bytes += packet.length as u64;
        }
        if self.packets.len() > 1000 {
            self.packets.drain(0..500);
        }
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
    }

    pub fn interface_down(&mut self) {
        if self.ui_focus != UIFocus::Interfaces {
            return;
        }
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
    }

    pub fn select_next_interface(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_interface_change) >= self.interface_change_delay {
            self.selected_interface = (self.selected_interface + 1) % self.interfaces.len();
            self.last_interface_change = now;
            self.interfaces_list_state
                .select(Some(self.selected_interface));
        }
    }

    pub fn select_prev_interface(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_interface_change) >= self.interface_change_delay {
            if self.selected_interface == 0 {
                self.selected_interface = self.interfaces.len() - 1;
            } else {
                self.selected_interface -= 1;
            }
            self.last_interface_change = now;
            self.interfaces_list_state
                .select(Some(self.selected_interface));
        }
    }

    pub fn select_next_packet(&mut self) {
        if self.ui_focus != UIFocus::Packets {
            return;
        }
        let i = match self.packets_table_state.selected() {
            Some(i) => {
                if i >= self.packets.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.packets_table_state.select(Some(i));
        self.selected_packet = Some(i);
        self.update_packet_detail(i);
    }

    pub fn select_prev_packet(&mut self) {
        if self.ui_focus != UIFocus::Packets {
            return;
        }
        let i = match self.packets_table_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.packets.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
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
        if let Some(packet) = self.packets.get(index) {
            let mut layers = Vec::new();
            layers.push(PacketLayer {
                name: "Ethernet Layer".to_string(),
                fields: vec![
                    ("Source MAC".to_string(), "00:1A:2B:3C:4D:5E".to_string()),
                    ("Destination MAC".to_string(), "AA:BB:CC:DD:EE:FF".to_string()),
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
                    ("Destination Address".to_string(), packet.destination.to_string()),
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
            let hex_dump = "0000: 00 1A 2B 3C 4D 5E AA BB  CC DD EE FF 08 00 45 00\n\
                          0010: 00 3C 12 34 40 00 40 06  8A BC C0 A8 01 64 08 08\n\
                          0020: 08 08 9C 40 00 50 12 34  56 78 00 00 00 00 50 02\n\
                          0030: 20 00 91 7C 00 00 47 45  54 20 2F 20 48 54 54 50\n\
                          0040: 2F 31 2E 31 0D 0A 48 6F  73 74 3A 20 65 78 61 6D\n\
                          0050: 70 6C 65 2E 63 6F 6D 0D  0A 55 73 65 72 2D 41 67\n\
                          0060: 65 6E 74 3A 20 78 6E 65  74 2F 30 2E 31 2E 30 0D"
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

    pub fn toggle_capture(&mut self) {
        self.capture_active = !self.capture_active;
    }

    pub fn on_tick(&mut self) {
        if self.capture_active {
            self.generate_mock_packets(1 + (self.packet_counter % 3) as usize);
        }
    }
}