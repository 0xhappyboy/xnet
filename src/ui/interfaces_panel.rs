use crate::app::{App, UIFocus};
use ratatui::{
    Frame,
    prelude::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

pub fn render_interfaces_panel(frame: &mut Frame, area: Rect, app: &App) {
    let selected_style = Style::default()
        .fg(Color::Yellow)
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD);
    let normal_style = Style::default().fg(Color::Gray);
    let items: Vec<ListItem> = app
        .interfaces
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
                    Span::raw("  RX: "),
                    Span::styled(
                        format!("{} packets", interface.packets_received),
                        Style::default().fg(Color::Green),
                    ),
                    Span::raw(" / "),
                    Span::styled(
                        format!("{} B", interface.bytes_received),
                        Style::default().fg(Color::Green),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("  TX: "),
                    Span::styled(
                        format!("{} packets", interface.packets_sent),
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::raw(" / "),
                    Span::styled(
                        format!("{} B", interface.bytes_sent),
                        Style::default().fg(Color::Yellow),
                    ),
                ]),
                Line::from(vec![
                    Span::raw("  Total: "),
                    Span::styled(
                        format!(
                            "{} packets",
                            interface.packets_received + interface.packets_sent
                        ),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::raw(" / "),
                    Span::styled(
                        format!("{} B", interface.bytes_received + interface.bytes_sent),
                        Style::default().fg(Color::Cyan),
                    ),
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
