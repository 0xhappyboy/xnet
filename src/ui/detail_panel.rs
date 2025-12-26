use crate::app::{App, UIFocus};
use ratatui::{
    Frame,
    prelude::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
};

pub fn render_detail_panel(frame: &mut Frame, area: Rect, app: &App) {
    let block_title = if app.ui_focus == UIFocus::Details {
        "Packet Details [Focused]"
    } else {
        "Packet Details"
    };
    let block = Block::default()
        .title(block_title)
        .borders(Borders::ALL)
        .style(if app.ui_focus == UIFocus::Details {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        });
    let inner_area = block.inner(area);
    frame.render_widget(block, area);
    if let Some(detail) = &app.packet_detail {
        let items: Vec<ListItem> = detail
            .layers
            .iter()
            .enumerate()
            .map(|(i, layer)| {
                let is_selected = app.selected_detail_layer == Some(i);
                let style = if is_selected && app.ui_focus == UIFocus::Details {
                    Style::default().bg(Color::DarkGray)
                } else {
                    Style::default()
                };
                let mut lines = vec![Line::from(vec![
                    Span::styled(
                        if is_selected { "▶ " } else { "  " },
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled(
                        &layer.name,
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!(" ({} fields)", layer.fields.len()),
                        Style::default().fg(Color::DarkGray),
                    ),
                ])];
                for (field, value) in &layer.fields {
                    lines.push(Line::from(vec![
                        Span::raw("    "),
                        Span::styled(field, Style::default().fg(Color::Cyan)),
                        Span::raw(": "),
                        Span::styled(value, Style::default().fg(Color::White)),
                    ]));
                }
                if i < detail.layers.len() - 1 {
                    lines.push(Line::from(Span::styled(
                        "─".repeat(inner_area.width as usize - 2),
                        Style::default().fg(Color::DarkGray),
                    )));
                }
                ListItem::new(lines).style(style)
            })
            .collect();
        let list = List::new(items).highlight_style(Style::default().bg(Color::DarkGray));
        frame.render_stateful_widget(list, inner_area, &mut app.details_list_state.clone());
        let stats_area = Rect {
            x: inner_area.x,
            y: inner_area.y + inner_area.height - 2,
            width: inner_area.width,
            height: 2,
        };
        let stats_text = format!(
            "Total Layers: {} | Current: {}",
            detail.layers.len(),
            app.selected_detail_layer
                .map_or("None".to_string(), |i| format!(
                    "{}/{}",
                    i + 1,
                    detail.layers.len()
                ))
        );
        let stats = Paragraph::new(Line::from(stats_text))
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::TOP));
        frame.render_widget(stats, stats_area);
    } else {
        let message = Paragraph::new(Line::from("Select a packet to view details"))
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::prelude::Alignment::Center);
        frame.render_widget(message, inner_area);
    }
}

pub fn render_hex_panel(frame: &mut Frame, area: Rect, app: &App) {
    let block_title = if app.ui_focus == UIFocus::Hex {
        "Hex Dump [Focused]"
    } else {
        "Hex Dump"
    };
    let block = Block::default()
        .title(block_title)
        .borders(Borders::ALL)
        .style(if app.ui_focus == UIFocus::Hex {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        });
    let inner_area = block.inner(area);
    frame.render_widget(block, area);
    if let Some(detail) = &app.packet_detail {
        let hex_lines: Vec<ListItem> = detail
            .hex_dump
            .lines()
            .enumerate()
            .map(|(i, line)| {
                let is_selected = app.selected_hex_line == Some(i);
                let style = if is_selected && app.ui_focus == UIFocus::Hex {
                    Style::default().bg(Color::DarkGray)
                } else {
                    Style::default()
                };
                let mut spans = Vec::new();
                let mut chars = line.chars().enumerate();
                while let Some((pos, c)) = chars.next() {
                    let char_style = if pos < 6 {
                        Style::default().fg(Color::DarkGray)
                    } else if pos >= 6 && pos < 55 {
                        let hex_char = format!("{}", c);
                        if hex_char != " " {
                            Style::default().fg(Color::Green)
                        } else {
                            Style::default().fg(Color::DarkGray)
                        }
                    } else {
                        if c.is_ascii_graphic() || c == ' ' {
                            Style::default().fg(Color::Yellow)
                        } else {
                            Style::default().fg(Color::Red)
                        }
                    };
                    spans.push(Span::styled(c.to_string(), char_style));
                }
                let mut full_line = vec![Span::styled(
                    format!("{:04X}: ", i * 16),
                    Style::default().fg(Color::DarkGray),
                )];
                full_line.extend(spans);
                ListItem::new(Line::from(full_line)).style(style)
            })
            .collect();
        let list = List::new(hex_lines).highlight_style(Style::default().bg(Color::DarkGray));
        frame.render_stateful_widget(list, inner_area, &mut app.hex_list_state.clone());
        let stats_area = Rect {
            x: inner_area.x,
            y: inner_area.y + inner_area.height - 2,
            width: inner_area.width,
            height: 2,
        };
        let line_count = detail.hex_dump.lines().count();
        let stats_text = format!(
            "Total Lines: {} | Current Line: {} | Offset: 0x{:04X}",
            line_count,
            app.selected_hex_line
                .map_or("None".to_string(), |i| format!("{}/{}", i + 1, line_count)),
            app.selected_hex_line.unwrap_or(0) * 16
        );
        let stats = Paragraph::new(Line::from(stats_text))
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::TOP));

        frame.render_widget(stats, stats_area);
    } else {
        let message = Paragraph::new(Line::from("Select a packet to view hex dump"))
            .style(Style::default().fg(Color::DarkGray))
            .alignment(ratatui::prelude::Alignment::Center);

        frame.render_widget(message, inner_area);
    }
}
