pub mod detail_panel;
pub mod interfaces_panel;
pub mod layout;
pub mod packets_table;

use crate::app::{App, UIFocus};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

fn render_status_bar(frame: &mut Frame, area: Rect, app: &App) {
    let interface = &app.interfaces[app.selected_interface];
    let focus_text = match app.ui_focus {
        UIFocus::Interfaces => "Interface Panel",
        UIFocus::Packets => "Packet List",
        UIFocus::Details => "Packet Details",
        UIFocus::Hex => "Hex Dump",
    };
    let status_text = format!(
        "xnet v0.1.0 | Focus: {} | Interface: {} | Status: {} | Packets: {} | Traffic: {} B",
        focus_text,
        interface.name,
        if app.capture_active {
            "Capturing"
        } else {
            "Paused"
        },
        app.total_packets,
        app.total_bytes
    );
    let status_style = if app.capture_active {
        Style::default().fg(Color::Green).bg(Color::DarkGray)
    } else {
        Style::default().fg(Color::Yellow).bg(Color::DarkGray)
    };
    let status_bar = Paragraph::new(Line::from(status_text))
        .style(status_style)
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(status_bar, area);
}

fn render_help_bar(frame: &mut Frame, area: Rect) {
    let help_items = vec![
        ("q", "Quit"),
        ("SPACE", "Start/Stop"),
        ("TAB", "Switch Panel"),
        ("↑↓", "Navigate in Current Panel"),
        ("r", "Clear List"),
    ];
    let help_spans: Vec<Span> = help_items
        .iter()
        .flat_map(|(key, desc)| {
            vec![
                Span::styled(
                    format!(" {} ", key),
                    Style::default().fg(Color::Black).bg(Color::White),
                ),
                Span::styled(format!(" {} ", desc), Style::default().fg(Color::Gray)),
                Span::raw("  "),
            ]
        })
        .collect();
    let help_line = Line::from(help_spans);
    let help_bar = Paragraph::new(help_line)
        .style(Style::default().bg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    frame.render_widget(help_bar, area);
}

pub fn render_ui(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(area);
    render_status_bar(frame, main_chunks[0], app);
    let content_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(20), Constraint::Percentage(80)])
        .split(main_chunks[1]);
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(content_chunks[1]);
    interfaces_panel::render_interfaces_panel(frame, content_chunks[0], app);
    packets_table::render_packets_table(frame, right_chunks[0], app);
    let detail_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(right_chunks[1]);
    detail_panel::render_detail_panel(frame, detail_chunks[0], app);
    detail_panel::render_hex_panel(frame, detail_chunks[1], app);
    render_help_bar(frame, main_chunks[2]);
}
