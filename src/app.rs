use crate::{
    net::{
        Network,
        scanner::{NetworkScanner, ScannerConfig},
    },
    types::{NetworkInterface, NetworkPacket, Packet, PacketDetail},
};
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
    pub current_interface: Option<NetworkInterface>,
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
    pub max_packets: Option<usize>,
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
        let interfaces = Self::get_interfaces(&network);
        Self {
            should_quit: false,
            ui_focus: UIFocus::Packets,
            capture_active: Arc::new(AtomicBool::new(false)),
            interfaces: interfaces.clone(),
            current_interface: None,
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
            max_packets: Some(5000),
        }
    }

    fn get_interfaces(network: &Network) -> Vec<NetworkInterface> {
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

    pub fn start_capture(&mut self) {
        self.capture_active.store(true, Ordering::SeqCst);
        if self.interfaces.is_empty() {
            return;
        }
        let config = ScannerConfig {
            filter_protocol: None,
        };
        let mut scanner = NetworkScanner::new(self.network.clone(), config);
        let (tx, rx) = std::sync::mpsc::channel::<Packet>();
        let packets_clone = self.packets.clone();
        let interface_name = self.current_interface.clone().unwrap().name.clone();
        let capture_active_clone = self.capture_active.clone();
        // max packets
        let max_packets_limit = self.max_packets;
        let processing_thread = thread::spawn(move || {
            while let Ok(packet) = rx.recv() {
                if !capture_active_clone.load(Ordering::SeqCst) {
                    continue;
                }
                let mut packets_write = packets_clone.write().unwrap();
                if let Some(max) = max_packets_limit {
                    if packets_write.len() >= max {
                        let to_remove = packets_write.len() - max + 1;
                        packets_write.drain(0..to_remove);
                    }
                }
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
            let temp_packet = Packet {
                timestamp: packet.timestamp.clone(),
                source: packet.source,
                destination: packet.destination,
                protocol: packet.protocol.clone(),
                length: packet.length,
                info: packet.info.clone(),
                raw_data: packet.raw_data.clone(),
            };
            let detail = NetworkScanner::generate_packet_detail(&temp_packet);
            let hex_dump = crate::net::generate_hex_dump(&packet.raw_data, 16);
            self.packet_detail = Some(PacketDetail {
                layers: detail.layers,
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
        } else {
            self.packet_detail = None;
            self.details_list_state.select(None);
            self.selected_detail_layer = None;
            self.hex_list_state.select(None);
            self.selected_hex_line = None;
        }
    }

    pub fn stop_capture(&mut self) {
        self.capture_active.store(false, Ordering::SeqCst);
    }

    pub fn toggle_capture(&mut self) {
        let was_capturing = self.capture_active.load(Ordering::SeqCst);
        if (was_capturing) {
            self.stop_capture();
        } else {
            self.capture_active.store(true, Ordering::SeqCst);
        }
    }

    pub fn refresh_interfaces(&mut self) {
        self.network.scan_interfaces();
        self.interfaces = Self::get_interfaces(&self.network);
    }
}
