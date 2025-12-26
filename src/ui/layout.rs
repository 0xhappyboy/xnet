use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
};

pub struct LayoutManager;

impl LayoutManager {
    pub fn create_main_layout(frame: &Frame) -> (Rect, Rect, Rect) {
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(frame.area());
        let content_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(main_chunks[1]);
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(content_chunks[1]);
        (content_chunks[0], right_chunks[0], right_chunks[1])
    }
}
