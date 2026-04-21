//! Event handling utilities for the Sicario TUI

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent};
use std::time::Duration;

/// Poll for a terminal event with the given timeout.
/// Returns `None` if no event arrived within the timeout.
pub fn poll_event(timeout: Duration) -> Result<Option<Event>> {
    if event::poll(timeout)? {
        Ok(Some(event::read()?))
    } else {
        Ok(None)
    }
}

/// Returns `true` if the event is a quit command (q or Esc).
pub fn is_quit_event(event: &Event) -> bool {
    matches!(
        event,
        Event::Key(KeyEvent { code: KeyCode::Char('q'), .. })
            | Event::Key(KeyEvent { code: KeyCode::Esc, .. })
    )
}

/// Returns `true` if the event is a downward navigation (↓ or j).
pub fn is_down_event(event: &Event) -> bool {
    matches!(
        event,
        Event::Key(KeyEvent { code: KeyCode::Down, .. })
            | Event::Key(KeyEvent { code: KeyCode::Char('j'), .. })
    )
}

/// Returns `true` if the event is an upward navigation (↑ or k).
pub fn is_up_event(event: &Event) -> bool {
    matches!(
        event,
        Event::Key(KeyEvent { code: KeyCode::Up, .. })
            | Event::Key(KeyEvent { code: KeyCode::Char('k'), .. })
    )
}

/// Returns `true` if the event is a confirmation (Enter).
pub fn is_enter_event(event: &Event) -> bool {
    matches!(event, Event::Key(KeyEvent { code: KeyCode::Enter, .. }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> Event {
        Event::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    #[test]
    fn test_quit_on_q() {
        assert!(is_quit_event(&key(KeyCode::Char('q'))));
    }

    #[test]
    fn test_quit_on_esc() {
        assert!(is_quit_event(&key(KeyCode::Esc)));
    }

    #[test]
    fn test_not_quit_on_enter() {
        assert!(!is_quit_event(&key(KeyCode::Enter)));
    }

    #[test]
    fn test_down_arrow() {
        assert!(is_down_event(&key(KeyCode::Down)));
        assert!(is_down_event(&key(KeyCode::Char('j'))));
        assert!(!is_down_event(&key(KeyCode::Up)));
    }

    #[test]
    fn test_up_arrow() {
        assert!(is_up_event(&key(KeyCode::Up)));
        assert!(is_up_event(&key(KeyCode::Char('k'))));
        assert!(!is_up_event(&key(KeyCode::Down)));
    }

    #[test]
    fn test_enter() {
        assert!(is_enter_event(&key(KeyCode::Enter)));
        assert!(!is_enter_event(&key(KeyCode::Char('y'))));
    }
}
