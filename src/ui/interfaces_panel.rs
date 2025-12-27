use crate::app::{App, InterfaceTrafficStats, UIFocus};
use ratatui::{
    Frame,
    prelude::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
};

pub fn render_interfaces_panel(frame: &mut Frame, area: Rect, app: &App) {
    let selected_style = Style::default()
        .fg(Color::Yellow)
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD);
    let normal_style = Style::default().fg(Color::Gray);
    let interfaces_read = app.interfaces.read().unwrap();
    let interface_stats = app.get_all_interface_stats();
    let items: Vec<ListItem> = interfaces_read
        .iter()
        .enumerate()
        .map(|(i, interface)| {
            let is_selected = i == app.selected_interface;
            let style = if is_selected {
                selected_style
            } else {
                normal_style
            };
            let status = if interface.is_up { "●" } else { "○" };
            let status_color = if interface.is_up {
                Color::Green
            } else {
                Color::Red
            };
            let binding = InterfaceTrafficStats::new(interface.name.clone());
            let traffic_stats = interface_stats
                .iter()
                .find(|stats| stats.name == interface.name)
                .unwrap_or(&binding);
            let format_bytes = |bytes: u64| {
                if bytes >= 1024 * 1024 * 1024 {
                    format!("{:.2} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
                } else if bytes >= 1024 * 1024 {
                    format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
                } else if bytes >= 1024 {
                    format!("{:.2} KiB", bytes as f64 / 1024.0)
                } else {
                    format!("{} B", bytes)
                }
            };
            let format_rate = |rate: u64| {
                if rate >= 1024 * 1024 {
                    format!("{:.2} MB/s", rate as f64 / (1024.0 * 1024.0))
                } else if rate >= 1024 {
                    format!("{:.2} KB/s", rate as f64 / 1024.0)
                } else {
                    format!("{} B/s", rate)
                }
            };
            let lines = vec![
                Line::from(vec![
                    Span::styled(status, Style::default().fg(status_color)),
                    Span::raw(" "),
                    Span::styled(&interface.name, style),
                    Span::raw(" ("),
                    Span::styled(&interface.description, Style::default().fg(Color::DarkGray)),
                    Span::raw(")"),
                ]),
                Line::from(vec![
                    Span::raw("  IP: "),
                    Span::styled(&interface.ip_address, Style::default().fg(Color::Blue)),
                ]),
                Line::from(vec![
                    Span::raw("  MAC: "),
                    Span::styled(&interface.mac_address, Style::default().fg(Color::Magenta)),
                ]),
                Line::from(vec![
                    Span::raw("  RX Rate: "),
                    Span::styled(
                        format_rate(traffic_stats.rx_bytes_per_sec),
                        Style::default().fg(Color::Green),
                    ),
                    Span::raw(" ("),
                    Span::styled(
                        format!("{} pkt/s", traffic_stats.rx_packets_per_sec),
                        Style::default().fg(Color::Green),
                    ),
                    Span::raw(")"),
                ]),
                Line::from(vec![
                    Span::raw("  TX Rate: "),
                    Span::styled(
                        format_rate(traffic_stats.tx_bytes_per_sec),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::raw(" ("),
                    Span::styled(
                        format!("{} pkt/s", traffic_stats.tx_packets_per_sec),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::raw(")"),
                ]),
                Line::from(vec![
                    Span::raw("  RX Total: "),
                    Span::styled(
                        format_bytes(interface.bytes_received),
                        Style::default().fg(Color::Green),
                    ),
                    Span::raw(" ("),
                    Span::styled(
                        format!("{} packets", interface.packets_received),
                        Style::default().fg(Color::Green),
                    ),
                    Span::raw(")"),
                ]),
                Line::from(vec![
                    Span::raw("  TX Total: "),
                    Span::styled(
                        format_bytes(interface.bytes_sent),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::raw(" ("),
                    Span::styled(
                        format!("{} packets", interface.packets_sent),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::raw(")"),
                ]),
                Line::from(vec![
                    Span::raw("  Total: "),
                    Span::styled(
                        format_bytes(interface.bytes_received + interface.bytes_sent),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(" ("),
                    Span::styled(
                        format!(
                            "{} packets",
                            interface.packets_received + interface.packets_sent
                        ),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(")"),
                ]),
            ];
            ListItem::new(lines).style(style)
        })
        .collect();
    let block_title = if app.ui_focus == UIFocus::Interfaces {
        "Network Interfaces [Focused]"
    } else {
        "Network Interfaces"
    };
    let list = List::new(items).block(
        Block::default()
            .title(block_title)
            .borders(Borders::ALL)
            .style(if app.ui_focus == UIFocus::Interfaces {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            }),
    );
    frame.render_stateful_widget(list, area, &mut app.interfaces_list_state.clone());
}
