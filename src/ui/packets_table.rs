use crate::{
    app::{App, UIFocus},
    types::Protocol,
};
use ratatui::{
    Frame,
    layout::Constraint,
    prelude::Rect,
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, Cell, Row, Table},
};

pub fn render_packets_table(frame: &mut Frame, area: Rect, app: &mut App) {
    let header = Row::new(vec![
        Cell::from("Time"),
        Cell::from("Source"),
        Cell::from("Destination"),
        Cell::from("Protocol"),
        Cell::from("Length"),
        Cell::from("Info"),
    ])
    .style(Style::default().fg(Color::Yellow))
    .height(1);
    let start_idx = app.packets.len().saturating_sub(50);
    let recent_packets = &app.packets[start_idx..];
    let rows: Vec<Row> = recent_packets
        .iter()
        .enumerate()
        .map(|(display_idx, packet)| {
            let actual_idx = start_idx + display_idx;
            let is_selected = app.selected_packet == Some(actual_idx);
            let protocol_color = match &packet.protocol {
                Protocol::TCP => Color::Green,
                Protocol::UDP => Color::Blue,
                Protocol::HTTP => Color::Cyan,
                Protocol::HTTPS => Color::Magenta,
                Protocol::DNS => Color::Yellow,
                Protocol::ICMP => Color::Red,
                Protocol::ARP => Color::LightRed,
                Protocol::IP => Color::Reset,
                Protocol::IPv6 => Color::LightMagenta,
                Protocol::Other(_) => Color::Gray,
            };
            let style = if is_selected {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(packet.timestamp.clone()),
                Cell::from(packet.source.to_string()),
                Cell::from(packet.destination.to_string()),
                Cell::from(format!("{:?}", packet.protocol))
                    .style(Style::default().fg(protocol_color)),
                Cell::from(packet.length.to_string()),
                Cell::from(packet.info.clone()),
            ])
            .style(style)
            .height(1)
        })
        .collect();
    let block_title = if app.ui_focus == UIFocus::Packets {
        "Network Packet List [Focused]"
    } else {
        "Network Packet List"
    };
    let table = Table::new(
        rows,
        [
            Constraint::Length(12),
            Constraint::Length(20),
            Constraint::Length(20),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Min(20),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title(block_title)
            .borders(Borders::ALL)
            .style(if app.ui_focus == UIFocus::Packets {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            }),
    )
    .highlight_style(Style::default().bg(Color::DarkGray));
    frame.render_stateful_widget(table, area, &mut app.packets_table_state);
    let stats_area = Rect {
        x: area.x + 1,
        y: area.y + area.height - 2,
        width: area.width - 2,
        height: 1,
    };
    let stats_text = format!(
        "Total: {} packets | {} B | Selected: {}",
        app.total_packets,
        app.total_bytes,
        app.selected_packet
            .map_or("None".to_string(), |i| format!("#{}", i))
    );
    let stats_line = Line::from(stats_text);
    let stats_paragraph =
        ratatui::widgets::Paragraph::new(stats_line).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(stats_paragraph, stats_area);
}
