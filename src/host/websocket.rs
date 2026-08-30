//! Watermark-only WebSocket invalidation for the Host runtime.

use std::panic::AssertUnwindSafe;

use axum::body::Body;
use axum::extract::{
    Request, State, WebSocketUpgrade,
    ws::{Message, rejection::WebSocketUpgradeRejection},
};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::FutureExt;
use serde::Serialize;
use tokio::sync::{broadcast, watch};

use super::http::{
    HttpState, invalid_request_response, projection_failure_response, request_has_body,
    request_has_query_properties, run_query,
};
use super::{RuntimeError, RuntimeErrorKind};
use crate::ProjectionCommit;

#[derive(Debug, Serialize)]
struct LiveEnvelope {
    http_schema_version: u8,
    delivery_sequence: String,
    projection_commit: LiveWatermark,
    payload: LivePayload,
}

#[derive(Debug, Serialize)]
struct LiveWatermark {
    store_id: String,
    sequence: String,
}

#[derive(Debug, Serialize)]
struct LivePayload {
    kind: &'static str,
}

pub(super) async fn handler(
    State(state): State<HttpState>,
    websocket: Result<WebSocketUpgrade, WebSocketUpgradeRejection>,
    request: Request,
) -> Response {
    let Ok(websocket) = websocket else {
        return upgrade_required();
    };
    if request_has_query_properties(&request) || request_has_body(&request) {
        return invalid_request_response("invalid live request");
    }
    let events = state.live.subscribe();
    let query = state.query;
    let watermark = match run_query(&state.control, move || query.projection_watermark()).await {
        Ok(watermark) => watermark,
        Err(()) => return projection_failure_response(),
    };
    let shutdown = state.control.shutdown.subscribe();
    let control = state.control;
    websocket
        .on_upgrade(move |socket| {
            supervise_socket(live_socket(socket, events, shutdown, watermark), control)
        })
        .into_response()
}

async fn supervise_socket<F>(socket: F, control: super::RuntimeControl)
where
    F: std::future::Future<Output = ()>,
{
    if AssertUnwindSafe(socket).catch_unwind().await.is_err() {
        control.fail(RuntimeError::new(RuntimeErrorKind::TaskPanicked("WebSocket")));
    }
}

async fn live_socket(
    mut socket: axum::extract::ws::WebSocket,
    mut events: broadcast::Receiver<ProjectionCommit>,
    mut shutdown: watch::Receiver<bool>,
    watermark: ProjectionCommit,
) {
    let store_id = watermark.store_id();
    let mut projection_sequence = watermark.sequence();
    let mut delivery_sequence = 0_u64;
    if !send_live(&mut socket, watermark, delivery_sequence, &mut shutdown).await {
        return;
    }
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            event = events.recv() => {
                let event = match event {
                    Ok(event) => event,
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        let Some(next_delivery) = delivery_sequence.checked_add(skipped) else {
                            break;
                        };
                        delivery_sequence = next_delivery;
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                };
                if event.store_id() != store_id || event.sequence() <= projection_sequence {
                    continue;
                }
                projection_sequence = event.sequence();
                let Some(next_delivery) = delivery_sequence.checked_add(1) else {
                    break;
                };
                delivery_sequence = next_delivery;
                if !send_live(&mut socket, event, delivery_sequence, &mut shutdown).await {
                    break;
                }
            }
        }
    }
}

async fn send_live(
    socket: &mut axum::extract::ws::WebSocket,
    event: ProjectionCommit,
    delivery_sequence: u64,
    shutdown: &mut watch::Receiver<bool>,
) -> bool {
    let envelope = LiveEnvelope {
        http_schema_version: 1,
        delivery_sequence: delivery_sequence.to_string(),
        projection_commit: LiveWatermark {
            store_id: crate::hex::encode(&event.store_id()),
            sequence: event.sequence().to_string(),
        },
        payload: LivePayload { kind: "projection_watermark" },
    };
    let Ok(text) = serde_json::to_string(&envelope) else {
        return false;
    };
    if *shutdown.borrow() {
        return false;
    }
    tokio::select! {
        changed = shutdown.changed() => changed.is_ok() && !*shutdown.borrow(),
        result = socket.send(Message::Text(text.into())) => result.is_ok(),
    }
}

fn upgrade_required() -> Response {
    Response::builder()
        .status(StatusCode::UPGRADE_REQUIRED)
        .header(header::CONTENT_LENGTH, "0")
        .body(Body::empty())
        .expect("fixed 426 response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn websocket_panic_requests_host_wide_stop() {
        let control = super::super::RuntimeControl::new();
        let _shutdown = control.shutdown.subscribe();
        supervise_socket(
            async {
                panic!("test WebSocket panic");
            },
            control.clone(),
        )
        .await;
        assert!(control.is_stopping());
        let error = control.take_fatal().expect("WebSocket panic retained as primary failure");
        assert_eq!(error.failure(), super::super::RuntimeFailure::Supervisor);
    }
}
