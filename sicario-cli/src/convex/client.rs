//! ConvexClient — WebSocket connection with JWT authentication, automatic
//! reconnection, telemetry push, and real-time ruleset subscription.
//!
//! Requirements: 8.1

use anyhow::{Context, Result};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::convex::ruleset::RulesetUpdate;
use crate::convex::telemetry::TelemetryEvent;

/// Current state of the WebSocket connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting { attempt: u32 },
}

/// Configuration for the Convex backend connection.
#[derive(Debug, Clone)]
pub struct ConvexConfig {
    /// WebSocket URL of the Convex deployment, e.g. `wss://your-project.convex.cloud`
    pub ws_url: String,
    /// JWT access token for Authorization header
    pub auth_token: String,
    /// Maximum number of reconnection attempts before giving up (0 = unlimited)
    pub max_reconnect_attempts: u32,
    /// Base delay between reconnection attempts (exponential backoff applied)
    pub reconnect_base_delay: Duration,
}

impl ConvexConfig {
    pub fn new(ws_url: impl Into<String>, auth_token: impl Into<String>) -> Self {
        Self {
            ws_url: ws_url.into(),
            auth_token: auth_token.into(),
            max_reconnect_attempts: 5,
            reconnect_base_delay: Duration::from_secs(2),
        }
    }
}

/// Internal messages sent over the command channel to the connection thread.
#[derive(Debug)]
enum ClientCommand {
    SendTelemetry(TelemetryEvent),
    SubscribeRulesets,
    Disconnect,
}

/// Events emitted by the connection thread back to the caller.
#[derive(Debug, Clone)]
pub enum ClientEvent {
    Connected,
    Disconnected,
    RulesetUpdate(RulesetUpdate),
    Error(String),
}

/// Convex backend client.
///
/// Manages a persistent WebSocket connection to the Convex backend.
/// Telemetry is pushed via `push_telemetry()` and ruleset updates are
/// received via the `Receiver<ClientEvent>` returned by `subscribe_rulesets()`.
pub struct ConvexClient {
    config: ConvexConfig,
    state: Arc<Mutex<ConnectionState>>,
    cmd_tx: Sender<ClientCommand>,
    event_rx: Receiver<ClientEvent>,
    _worker: thread::JoinHandle<()>,
}

impl ConvexClient {
    /// Create a new `ConvexClient` and immediately begin connecting.
    ///
    /// The underlying WebSocket connection is managed on a background thread.
    /// Use `push_telemetry()` to send events and `subscribe_rulesets()` to
    /// receive real-time ruleset updates.
    pub fn new(config: ConvexConfig) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel::<ClientCommand>();
        let (event_tx, event_rx) = mpsc::channel::<ClientEvent>();
        let state = Arc::new(Mutex::new(ConnectionState::Disconnected));
        let state_clone = Arc::clone(&state);
        let cfg = config.clone();

        let worker = thread::spawn(move || {
            run_connection_loop(cfg, cmd_rx, event_tx, state_clone);
        });

        Self {
            config,
            state,
            cmd_tx,
            event_rx,
            _worker: worker,
        }
    }

    /// Return the current connection state.
    pub fn connection_state(&self) -> ConnectionState {
        self.state.lock().unwrap().clone()
    }

    /// Push a telemetry event to the Convex backend.
    ///
    /// The event is queued and sent over the WebSocket connection.
    /// If the connection is temporarily unavailable the event will be
    /// sent once the connection is re-established.
    ///
    /// Requirements: 8.2
    pub fn push_telemetry(&self, event: TelemetryEvent) -> Result<()> {
        self.cmd_tx
            .send(ClientCommand::SendTelemetry(event))
            .context("Failed to queue telemetry event — connection thread has stopped")?;
        Ok(())
    }

    /// Subscribe to real-time ruleset updates.
    ///
    /// Sends a subscription request to the Convex backend and returns a
    /// `Receiver` that yields `ClientEvent::RulesetUpdate` messages whenever
    /// the organizational ruleset changes.
    ///
    /// Requirements: 8.4
    pub fn subscribe_rulesets(&self) -> Result<&Receiver<ClientEvent>> {
        self.cmd_tx
            .send(ClientCommand::SubscribeRulesets)
            .context("Failed to send subscribe command — connection thread has stopped")?;
        Ok(&self.event_rx)
    }

    /// Gracefully disconnect from the Convex backend.
    pub fn disconnect(&self) {
        let _ = self.cmd_tx.send(ClientCommand::Disconnect);
    }

    /// Drain all pending events without blocking.
    pub fn drain_events(&self) -> Vec<ClientEvent> {
        self.event_rx.try_iter().collect()
    }
}

// ── Connection loop ──────────────────────────────────────────────────────────

/// Runs on the background thread. Manages the WebSocket lifecycle including
/// initial connection, message dispatch, and automatic reconnection.
fn run_connection_loop(
    config: ConvexConfig,
    cmd_rx: Receiver<ClientCommand>,
    event_tx: Sender<ClientEvent>,
    state: Arc<Mutex<ConnectionState>>,
) {
    let mut attempt: u32 = 0;

    loop {
        // Update state to Connecting / Reconnecting
        {
            let mut s = state.lock().unwrap();
            *s = if attempt == 0 {
                ConnectionState::Connecting
            } else {
                ConnectionState::Reconnecting { attempt }
            };
        }

        info!(
            "ConvexClient: connecting to {} (attempt {})",
            config.ws_url,
            attempt + 1
        );

        match connect_and_run(&config, &cmd_rx, &event_tx, &state) {
            Ok(should_stop) => {
                if should_stop {
                    info!("ConvexClient: disconnected by request");
                    break;
                }
                // Clean disconnect — reconnect
                warn!("ConvexClient: connection closed, will reconnect");
            }
            Err(e) => {
                error!("ConvexClient: connection error: {}", e);
                let _ = event_tx.send(ClientEvent::Error(e.to_string()));
            }
        }

        attempt += 1;

        // Check reconnect limit
        if config.max_reconnect_attempts > 0 && attempt >= config.max_reconnect_attempts {
            error!(
                "ConvexClient: exceeded max reconnect attempts ({}), giving up",
                config.max_reconnect_attempts
            );
            break;
        }

        // Exponential backoff: base * 2^attempt, capped at 60 s
        let delay = config
            .reconnect_base_delay
            .mul_f64(2_f64.powi(attempt as i32 - 1))
            .min(Duration::from_secs(60));

        info!("ConvexClient: reconnecting in {:?}", delay);
        thread::sleep(delay);
    }

    let mut s = state.lock().unwrap();
    *s = ConnectionState::Disconnected;
}

/// Attempt a single WebSocket connection and process messages until the
/// connection closes or a `Disconnect` command is received.
///
/// Returns `Ok(true)` if the caller should stop (Disconnect command received),
/// `Ok(false)` if the connection closed normally and should be retried,
/// or `Err` on a fatal error.
fn connect_and_run(
    config: &ConvexConfig,
    cmd_rx: &Receiver<ClientCommand>,
    event_tx: &Sender<ClientEvent>,
    state: &Arc<Mutex<ConnectionState>>,
) -> Result<bool> {
    use tungstenite::{
        client::IntoClientRequest,
        connect,
        Message,
    };

    // Build the WebSocket request with the Authorization header
    let mut request = config
        .ws_url
        .as_str()
        .into_client_request()
        .context("Invalid WebSocket URL")?;

    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}", config.auth_token)
            .parse()
            .context("Invalid auth token for header")?,
    );

    // Establish the connection
    let (mut ws, _response) = connect(request).context("WebSocket connection failed")?;

    // Mark as connected
    {
        let mut s = state.lock().unwrap();
        *s = ConnectionState::Connected;
    }
    let _ = event_tx.send(ClientEvent::Connected);
    info!("ConvexClient: connected");

    // Set the underlying TCP stream to non-blocking so we can interleave
    // command polling with message reading.
    if let tungstenite::stream::MaybeTlsStream::Plain(ref tcp) = *ws.get_ref() {
        tcp.set_read_timeout(Some(Duration::from_millis(50))).ok();
    }

    loop {
        // ── Drain pending commands ────────────────────────────────────────
        loop {
            match cmd_rx.try_recv() {
                Ok(ClientCommand::Disconnect) => {
                    let _ = ws.close(None);
                    return Ok(true);
                }
                Ok(ClientCommand::SendTelemetry(event)) => {
                    let payload = serde_json::to_string(&event)
                        .unwrap_or_else(|_| "{}".to_string());
                    let msg = build_mutation_message("pushTelemetry", &payload);
                    if let Err(e) = ws.send(Message::Text(msg)) {
                        warn!("ConvexClient: failed to send telemetry: {}", e);
                    } else {
                        debug!("ConvexClient: telemetry sent");
                    }
                }
                Ok(ClientCommand::SubscribeRulesets) => {
                    let msg = build_subscribe_message("rulesets");
                    if let Err(e) = ws.send(Message::Text(msg)) {
                        warn!("ConvexClient: failed to subscribe to rulesets: {}", e);
                    } else {
                        debug!("ConvexClient: subscribed to rulesets");
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // Caller dropped the client — clean up
                    let _ = ws.close(None);
                    return Ok(true);
                }
            }
        }

        // ── Read incoming WebSocket messages ──────────────────────────────
        match ws.read() {
            Ok(Message::Text(text)) => {
                debug!("ConvexClient: received message: {}", text);
                if let Some(event) = parse_server_message(&text) {
                    let _ = event_tx.send(event);
                }
            }
            Ok(Message::Ping(data)) => {
                let _ = ws.send(Message::Pong(data));
            }
            Ok(Message::Close(_)) => {
                info!("ConvexClient: server closed connection");
                let _ = event_tx.send(ClientEvent::Disconnected);
                return Ok(false);
            }
            Ok(_) => {} // Binary / Pong / etc. — ignore
            Err(tungstenite::Error::Io(ref e))
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                // Non-blocking timeout — normal, just loop again
            }
            Err(e) => {
                return Err(anyhow::anyhow!("WebSocket read error: {}", e));
            }
        }
    }
}

// ── Message builders ─────────────────────────────────────────────────────────

/// Build a Convex mutation message in the Convex protocol format.
fn build_mutation_message(function_name: &str, args_json: &str) -> String {
    serde_json::json!({
        "type": "Mutation",
        "requestId": uuid::Uuid::new_v4().to_string(),
        "udfPath": function_name,
        "args": [serde_json::from_str::<serde_json::Value>(args_json)
            .unwrap_or(serde_json::Value::Null)]
    })
    .to_string()
}

/// Build a Convex query subscription message.
fn build_subscribe_message(query_name: &str) -> String {
    serde_json::json!({
        "type": "Subscribe",
        "requestId": uuid::Uuid::new_v4().to_string(),
        "udfPath": query_name,
        "args": [{}]
    })
    .to_string()
}

/// Parse an incoming server message and convert it to a `ClientEvent`.
fn parse_server_message(text: &str) -> Option<ClientEvent> {
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    let msg_type = value.get("type")?.as_str()?;

    match msg_type {
        "QueryUpdated" => {
            // Ruleset update from a subscription
            let result = value.get("value")?;
            let update: crate::convex::ruleset::RulesetUpdate =
                serde_json::from_value(result.clone()).ok()?;
            Some(ClientEvent::RulesetUpdate(update))
        }
        "FunctionResult" => {
            // Mutation acknowledgement — no action needed
            None
        }
        _ => None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convex_config_defaults() {
        let cfg = ConvexConfig::new("wss://example.convex.cloud", "token123");
        assert_eq!(cfg.ws_url, "wss://example.convex.cloud");
        assert_eq!(cfg.auth_token, "token123");
        assert_eq!(cfg.max_reconnect_attempts, 5);
        assert_eq!(cfg.reconnect_base_delay, Duration::from_secs(2));
    }

    #[test]
    fn test_connection_state_variants() {
        let s1 = ConnectionState::Disconnected;
        let s2 = ConnectionState::Connecting;
        let s3 = ConnectionState::Connected;
        let s4 = ConnectionState::Reconnecting { attempt: 3 };
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
        assert_ne!(s3, s4);
    }

    #[test]
    fn test_build_mutation_message_is_valid_json() {
        let msg = build_mutation_message("pushTelemetry", r#"{"key":"value"}"#);
        let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(parsed["type"], "Mutation");
        assert_eq!(parsed["udfPath"], "pushTelemetry");
        assert!(parsed["requestId"].is_string());
    }

    #[test]
    fn test_build_subscribe_message_is_valid_json() {
        let msg = build_subscribe_message("rulesets");
        let parsed: serde_json::Value = serde_json::from_str(&msg).unwrap();
        assert_eq!(parsed["type"], "Subscribe");
        assert_eq!(parsed["udfPath"], "rulesets");
    }

    #[test]
    fn test_parse_server_message_ruleset_update() {
        let text = serde_json::json!({
            "type": "QueryUpdated",
            "value": {
                "version": 2,
                "rules": []
            }
        })
        .to_string();

        let event = parse_server_message(&text);
        assert!(matches!(event, Some(ClientEvent::RulesetUpdate(_))));
    }

    #[test]
    fn test_parse_server_message_unknown_type() {
        let text = r#"{"type":"Unknown","data":{}}"#;
        let event = parse_server_message(text);
        assert!(event.is_none());
    }

    #[test]
    fn test_parse_server_message_invalid_json() {
        let event = parse_server_message("not json at all");
        assert!(event.is_none());
    }
}
