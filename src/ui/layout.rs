use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    Frame,
};

pub struct LayoutManager;

impl LayoutManager {
    pub fn create_main_layout(frame: &Frame) -> (Rect, Rect, Rect) {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),    // Top status bar
                Constraint::Min(10),      // Main content area
                Constraint::Length(3),    // Bottom status bar
            ])
            .split(frame.area());
        let content_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(30),  // Left: interface list
                Constraint::Percentage(70),  // Right: packet list and details
            ])
            .split(main_chunks[1]);
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(60),  // Packet list
                Constraint::Percentage(40),  // Packet details
            ])
            .split(content_chunks[1]);
        (content_chunks[0], right_chunks[0], right_chunks[1])
    }
}