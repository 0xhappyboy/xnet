mod app;
mod net;
mod protocol;
mod types;
mod ui;

use app::App;
use ratatui::{Terminal, backend::CrosstermBackend};
use std::{
    io,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};

fn main() -> Result<(), io::Error> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();
    let tick_rate = Duration::from_millis(100);
    let mut last_tick = Instant::now();
    let res = run_app(&mut terminal, &mut app, tick_rate, &mut last_tick);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    if let Err(err) = res {
        println!("Error: {:?}", err);
    }
    Ok(())
}

fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    tick_rate: Duration,
    last_tick: &mut Instant,
) -> io::Result<()> {
    loop {
        terminal.draw(|frame| ui::render_ui(frame, app))?;
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != crossterm::event::KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') => {
                        app.should_quit = true;
                        return Ok(());
                    }
                    KeyCode::Char(' ') => {
                        if app.ui_focus == app::UIFocus::Interfaces {
                            let list_selected = app.interfaces_list_state.selected();
                            if let Some(selected_idx) = list_selected {
                                if selected_idx < app.interfaces.len() {
                                    let list_iface = &app.interfaces[selected_idx];
                                    let mut should_change = false;
                                    if app.current_interface.is_none() {
                                        app.current_interface = Some(list_iface.clone());
                                        should_change = true;
                                    } else {
                                        should_change = match &app.current_interface {
                                            Some(current_iface) => {
                                                current_iface.name != list_iface.name
                                            }
                                            None => true,
                                        };
                                    }
                                    if should_change {
                                        app.current_interface = Some(list_iface.clone());
                                        app.selected_interface = selected_idx;
                                        let was_capturing =
                                            app.capture_active.load(Ordering::SeqCst);
                                        if was_capturing {
                                            app.toggle_capture();
                                            std::thread::sleep(Duration::from_millis(100));
                                            app.clear_packets();
                                            app.start_capture();
                                        } else {
                                            app.clear_packets();
                                            app.start_capture();
                                        }
                                    } else {
                                        app.toggle_capture();
                                    }
                                }
                            } else {
                                app.toggle_capture();
                            }
                        } else {
                            app.toggle_capture();
                        }
                    }
                    KeyCode::Tab if key.modifiers.contains(KeyModifiers::SHIFT) => {
                        match app.ui_focus {
                            app::UIFocus::Interfaces => app.ui_focus = app::UIFocus::Hex,
                            app::UIFocus::Packets => app.ui_focus = app::UIFocus::Interfaces,
                            app::UIFocus::Details => app.ui_focus = app::UIFocus::Packets,
                            app::UIFocus::Hex => app.ui_focus = app::UIFocus::Details,
                        }
                    }
                    KeyCode::Tab => {
                        app.focus_next();
                    }
                    KeyCode::Up => match app.ui_focus {
                        app::UIFocus::Interfaces => app.interface_up(),
                        app::UIFocus::Packets => app.select_prev_packet(),
                        app::UIFocus::Details => app.detail_up(),
                        app::UIFocus::Hex => app.hex_up(),
                    },
                    KeyCode::Down => match app.ui_focus {
                        app::UIFocus::Interfaces => app.interface_down(),
                        app::UIFocus::Packets => app.select_next_packet(),
                        app::UIFocus::Details => app.detail_down(),
                        app::UIFocus::Hex => app.hex_down(),
                    },
                    KeyCode::Char('r') => {
                        app.clear_packets();
                    }
                    KeyCode::Char('i') => {
                        app.refresh_interfaces();
                    }
                    _ => {}
                }
            }
        }
        if last_tick.elapsed() >= tick_rate {
            *last_tick = Instant::now();
        }
        if app.should_quit {
            return Ok(());
        }
    }
}
