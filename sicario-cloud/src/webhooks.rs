//! Async webhook dispatcher for Slack, Teams, PagerDuty, and custom HTTP endpoints.
//!
//! Fires on: new Critical findings, SLA breaches, scan failures.
//! Requirements: 21.27

use crate::db::{AppState, WebhookDelivery};
use crate::models::{WebhookConfig, WebhookDeliveryType, WebhookEventType};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use tracing::{error, info};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Dispatch webhooks for a given event type. Runs asynchronously and does not
/// block the API response.
pub async fn dispatch_webhooks(
    state: &AppState,
    event_type: WebhookEventType,
    payload: serde_json::Value,
) {
    let webhooks = state
        .store
        .get_enabled_webhooks_for_event(&event_type)
        .await;

    for webhook in webhooks {
        let client = state.webhook_client.clone();
        let payload = payload.clone();
        let store = state.store.clone();

        tokio::spawn(async move {
            let result = deliver_webhook(&client, &webhook, &event_type, &payload).await;

            let delivery = WebhookDelivery {
                id: Uuid::new_v4(),
                webhook_id: webhook.id,
                event_type: event_type.to_string(),
                payload: payload.clone(),
                status: if result.is_ok() {
                    "delivered".to_string()
                } else {
                    "failed".to_string()
                },
                response_code: result.ok(),
                delivered_at: Utc::now(),
            };

            store.record_webhook_delivery(delivery).await;
        });
    }
}

/// Deliver a single webhook to its configured endpoint.
async fn deliver_webhook(
    client: &reqwest::Client,
    webhook: &WebhookConfig,
    event_type: &WebhookEventType,
    payload: &serde_json::Value,
) -> Result<i32, anyhow::Error> {
    let body = format_payload(webhook.delivery_type, event_type, payload);

    let mut request = client
        .post(&webhook.url)
        .header("Content-Type", "application/json")
        .header("X-Sicario-Event", event_type.to_string());

    // HMAC-SHA256 signature if secret is configured (standard webhook signing)
    if let Some(ref secret) = webhook.secret {
        let body_bytes = serde_json::to_vec(&body)?;
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| anyhow::anyhow!("HMAC key error: {e}"))?;
        mac.update(&body_bytes);
        let signature = format!("sha256={:x}", mac.finalize().into_bytes());
        request = request.header("X-Sicario-Signature", signature);
    }

    let response = request
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await?;

    let status = response.status().as_u16() as i32;

    if response.status().is_success() {
        info!(webhook_id = %webhook.id, event = %event_type, "Webhook delivered successfully");
    } else {
        error!(webhook_id = %webhook.id, event = %event_type, status, "Webhook delivery failed");
    }

    Ok(status)
}

/// Format the payload according to the delivery type (Slack, Teams, PagerDuty, HTTP).
fn format_payload(
    delivery_type: WebhookDeliveryType,
    event_type: &WebhookEventType,
    payload: &serde_json::Value,
) -> serde_json::Value {
    match delivery_type {
        WebhookDeliveryType::Slack => {
            json!({
                "text": format!(":rotating_light: Sicario Alert: {}", event_type),
                "blocks": [{
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": format!("*Sicario Alert*: `{}`\n```{}```", event_type, payload)
                    }
                }]
            })
        }
        WebhookDeliveryType::Teams => {
            json!({
                "@type": "MessageCard",
                "summary": format!("Sicario Alert: {}", event_type),
                "themeColor": "FF0000",
                "sections": [{
                    "activityTitle": format!("Sicario Alert: {}", event_type),
                    "text": format!("{}", payload)
                }]
            })
        }
        WebhookDeliveryType::Pagerduty => {
            // PagerDuty routing key should be stored in the webhook secret field
            let routing_key = payload
                .get("routing_key")
                .and_then(|v| v.as_str())
                .filter(|k| !k.is_empty())
                .unwrap_or("configure_pagerduty_routing_key");
            json!({
                "routing_key": routing_key,
                "event_action": "trigger",
                "payload": {
                    "summary": format!("Sicario: {}", event_type),
                    "severity": "critical",
                    "source": "sicario-cloud",
                    "custom_details": payload
                }
            })
        }
        WebhookDeliveryType::Http => {
            json!({
                "event": event_type.to_string(),
                "timestamp": Utc::now().to_rfc3339(),
                "data": payload
            })
        }
    }
}
