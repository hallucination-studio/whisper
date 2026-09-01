//! Strict loopback HTTP and bounded WebSocket delivery for the Host runtime.

use std::collections::BTreeMap;
use std::io;
use std::net::{Shutdown, SocketAddr};
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::Router;
use axum::extract::{Json, OriginalUri, Query, Request, State, rejection::QueryRejection};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{MethodFilter, on};
use axum::serve::Listener;
use serde::Deserialize;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

use super::{RuntimeControl, RuntimeError, RuntimeErrorKind, SocketOperation, SocketRole};
use crate::ProjectionCommit;
use crate::domain::time::SessionTime;
use crate::store::{
    ErrorEnvelope, Metric, QueryError, QueryLimits, QueryStore, RelationshipSelection, SignalPath,
    SignalQuery, SignalRange, SignalSelection,
};

/// Maximum digits in the canonical decimal representation of a `u64`.
const MAX_U64_DECIMAL_DIGITS: usize = 20;

const PAGE_SHELL: &str = include_str!("assets/index.html");
const PAGE_STYLES: &str = include_str!("assets/app.css");
const PAGE_SCRIPT: &str = include_str!("assets/app.js");

#[derive(Clone)]
pub(super) struct HttpState {
    pub(super) query: QueryStore,
    pub(super) limits: QueryLimits,
    pub(super) live: broadcast::Sender<ProjectionCommit>,
    pub(super) relationship_commands: crate::application::RelationshipCommandIngress,
    pub(super) control: RuntimeControl,
}

#[derive(Clone, Default)]
pub(super) struct ConnectionRegistry {
    inner: Arc<Mutex<RegistryState>>,
}

#[derive(Default)]
struct RegistryState {
    next_id: u64,
    connections: BTreeMap<u64, std::net::TcpStream>,
}

impl ConnectionRegistry {
    fn track(&self, shutdown: std::net::TcpStream) -> io::Result<u64> {
        let mut state = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let id = state
            .next_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("HTTP connection identity overflow"))?;
        state.next_id = id;
        state.connections.insert(id, shutdown);
        Ok(id)
    }

    fn remove(&self, id: u64) {
        let mut state = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.connections.remove(&id);
    }

    pub(super) fn shutdown_all(&self) {
        let state = self.inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for connection in state.connections.values() {
            let _ = connection.shutdown(Shutdown::Both);
        }
    }
}

pub(super) struct TrackedListener {
    listener: TcpListener,
    registry: ConnectionRegistry,
    control: RuntimeControl,
    address: SocketAddr,
}

impl TrackedListener {
    pub(super) const fn new(
        listener: TcpListener,
        registry: ConnectionRegistry,
        control: RuntimeControl,
        address: SocketAddr,
    ) -> Self {
        Self { listener, registry, control, address }
    }
}

pub(super) struct TrackedStream {
    stream: tokio::net::TcpStream,
    registry: ConnectionRegistry,
    id: u64,
}

impl Drop for TrackedStream {
    fn drop(&mut self) {
        self.registry.remove(self.id);
    }
}

impl AsyncRead for TrackedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for TrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl Listener for TrackedListener {
    type Io = TrackedStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = match self.listener.accept().await {
                Ok(connection) => connection,
                Err(source) => {
                    self.control.fail(RuntimeError::socket(
                        SocketRole::Http,
                        SocketOperation::Accept,
                        self.address,
                        source,
                    ));
                    std::future::pending::<()>().await;
                    continue;
                }
            };
            let standard = match stream.into_std() {
                Ok(stream) => stream,
                Err(source) => {
                    self.control.fail(RuntimeError::socket(
                        SocketRole::Http,
                        SocketOperation::Track,
                        self.address,
                        source,
                    ));
                    continue;
                }
            };
            let shutdown = match standard.try_clone() {
                Ok(shutdown) => shutdown,
                Err(source) => {
                    self.control.fail(RuntimeError::socket(
                        SocketRole::Http,
                        SocketOperation::Track,
                        self.address,
                        source,
                    ));
                    continue;
                }
            };
            let stream = match tokio::net::TcpStream::from_std(standard) {
                Ok(stream) => stream,
                Err(source) => {
                    self.control.fail(RuntimeError::socket(
                        SocketRole::Http,
                        SocketOperation::Track,
                        self.address,
                        source,
                    ));
                    continue;
                }
            };
            let id = match self.registry.track(shutdown) {
                Ok(id) => id,
                Err(source) => {
                    self.control.fail(RuntimeError::socket(
                        SocketRole::Http,
                        SocketOperation::Track,
                        self.address,
                        source,
                    ));
                    continue;
                }
            };
            return (TrackedStream { stream, registry: self.registry.clone(), id }, address);
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignalParameters {
    session: String,
    sensor: String,
    link: String,
    from: String,
    to: String,
    metric: String,
    max_time_buckets: String,
    profile: Option<String>,
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationshipParameters {
    session: String,
    link: String,
    profile: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelationshipCommandRequest {
    http_schema_version: u8,
    target: RelationshipCommandTarget,
    command: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelationshipCommandTarget {
    link: String,
    profile: String,
}

#[derive(Debug, Serialize)]
struct RelationshipCommandAccepted {
    http_schema_version: u8,
    kind: &'static str,
    resource: &'static str,
    target: RelationshipCommandTarget,
    correlation_id: String,
}

pub(super) fn router(
    query: QueryStore,
    limits: QueryLimits,
    live: broadcast::Sender<ProjectionCommit>,
    relationship_commands: crate::application::RelationshipCommandIngress,
    control: RuntimeControl,
) -> Router {
    Router::new()
        .route("/", on(MethodFilter::GET, index))
        .route("/assets/app.css", on(MethodFilter::GET, stylesheet))
        .route("/assets/app.js", on(MethodFilter::GET, script))
        .route(
            "/api/topology",
            on(MethodFilter::GET, topology).on(MethodFilter::HEAD, method_not_allowed),
        )
        .route(
            "/api/signals",
            on(MethodFilter::GET, signals).on(MethodFilter::HEAD, method_not_allowed),
        )
        .route(
            "/api/live",
            on(MethodFilter::GET, super::websocket::handler)
                .on(MethodFilter::HEAD, method_not_allowed),
        )
        .route(
            "/api/relationships/latest",
            on(MethodFilter::GET, relationship_latest).on(MethodFilter::HEAD, method_not_allowed),
        )
        .route(
            "/api/relationships/commands",
            on(MethodFilter::POST, relationship_command).fallback(relationship_command_method),
        )
        .with_state(HttpState { query, limits, live, relationship_commands, control })
}

async fn relationship_command_method() -> Response {
    invalid_request_response("invalid relationship command")
}

async fn relationship_command(
    State(state): State<HttpState>,
    OriginalUri(uri): OriginalUri,
    body: Result<Json<RelationshipCommandRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if uri.query().is_some_and(|query| !query.is_empty()) {
        return invalid_request_response("invalid relationship command");
    }
    let Ok(Json(request)) = body else {
        return invalid_request_response("invalid relationship command");
    };
    if request.http_schema_version != 1 {
        return invalid_request_response("invalid relationship command");
    }
    let command = match request.command.as_str() {
        "begin_learning" => crate::domain::world::BaselineCommand::BeginLearning,
        "commit" => crate::domain::world::BaselineCommand::Commit,
        _ => return invalid_request_response("invalid relationship command"),
    };
    let Ok(link) = crate::domain::identity::RadioLinkId::new(request.target.link.as_str()) else {
        return invalid_request_response("invalid relationship command");
    };
    let Ok(profile) = decode_profile(&request.target.profile) else {
        return invalid_request_response("invalid relationship command");
    };
    match state.relationship_commands.try_command(link, profile, command) {
        Ok(correlation_id) => (
            StatusCode::ACCEPTED,
            Json(RelationshipCommandAccepted {
                http_schema_version: 1,
                kind: "accepted",
                resource: "relationship_command",
                target: request.target,
                correlation_id,
            }),
        )
            .into_response(),
        Err(crate::application::RelationshipCommandAdmissionError::QueueFull) => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(ErrorEnvelope::command_queue_full()))
                .into_response()
        }
        Err(_) => invalid_request_response("invalid relationship command"),
    }
}

fn decode_profile(value: &str) -> Result<crate::domain::csi::CaptureProfileId, ()> {
    if value.len() != 64
        || value.bytes().any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(());
    }
    let mut decoded = [0_u8; 32];
    for (target, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = char::from(pair[0]).to_digit(16).ok_or(())?;
        let low = char::from(pair[1]).to_digit(16).ok_or(())?;
        *target = u8::try_from((high << 4) | low).map_err(|_| ())?;
    }
    Ok(crate::domain::csi::CaptureProfileId::from_bytes(decoded))
}

pub(super) fn bind_socket(address: SocketAddr) -> Result<TcpListener, RuntimeError> {
    let listener = std::net::TcpListener::bind(address).map_err(|source| {
        RuntimeError::socket(SocketRole::Http, SocketOperation::Bind, address, source)
    })?;
    listener.set_nonblocking(true).map_err(|source| {
        RuntimeError::socket(SocketRole::Http, SocketOperation::Configure, address, source)
    })?;
    TcpListener::from_std(listener).map_err(|source| {
        RuntimeError::socket(SocketRole::Http, SocketOperation::Configure, address, source)
    })
}

async fn index(State(state): State<HttpState>) -> Html<String> {
    Html(PAGE_SHELL.replace("__MAX_TIME_BUCKETS__", &state.limits.max_time_buckets().to_string()))
}

async fn stylesheet() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], PAGE_STYLES)
}

async fn script() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8")], PAGE_SCRIPT)
}

async fn method_not_allowed() -> StatusCode {
    StatusCode::METHOD_NOT_ALLOWED
}

async fn topology(State(state): State<HttpState>, request: Request) -> Response {
    if request_has_query_properties(&request) || request_has_body(&request) {
        return invalid_request_response("invalid topology request");
    }
    let query = state.query;
    match run_query(&state.control, move || query.topology()).await {
        Ok(body) => Json(body).into_response(),
        Err(()) => projection_failure_response(),
    }
}

async fn signals(
    State(state): State<HttpState>,
    parameters: Result<Query<SignalParameters>, QueryRejection>,
    request: Request,
) -> Response {
    if request_has_body(&request) {
        return invalid_request_response("invalid signal query");
    }
    let parameters = match parameters {
        Ok(Query(parameters)) => parameters,
        Err(_) => return invalid_request_response("invalid signal query"),
    };
    let query = match decode_signal_query(parameters) {
        Ok(query) => query,
        Err(_) => return invalid_request_response("invalid signal query"),
    };
    let control = state.control.clone();
    match run_query(&control, move || state.query.signals(&query, state.limits)).await {
        Ok(response) => {
            let status = StatusCode::from_u16(response.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, Json(response)).into_response()
        }
        Err(()) => projection_failure_response(),
    }
}

async fn relationship_latest(
    State(state): State<HttpState>,
    OriginalUri(uri): OriginalUri,
    parameters: Result<Query<RelationshipParameters>, QueryRejection>,
    request: Request,
) -> Response {
    if request_has_body(&request) {
        return invalid_request_response("invalid relationship query");
    }
    let control = state.control.clone();
    match uri.query() {
        None => match run_query(&control, move || state.query.relationship_subjects()).await {
            Ok(response) => Json(response).into_response(),
            Err(()) => projection_failure_response(),
        },
        Some("") => invalid_request_response("invalid relationship query"),
        Some(_) => {
            let Ok(Query(parameters)) = parameters else {
                return invalid_request_response("invalid relationship query");
            };
            let Ok(selection) = RelationshipSelection::try_new(
                &parameters.session,
                &parameters.link,
                &parameters.profile,
            ) else {
                return invalid_request_response("invalid relationship query");
            };
            match run_query(&control, move || state.query.relationship_latest(&selection)).await {
                Ok(response) => {
                    let status = StatusCode::from_u16(response.http_status())
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                    (status, Json(response)).into_response()
                }
                Err(()) => projection_failure_response(),
            }
        }
    }
}

fn decode_signal_query(parameters: SignalParameters) -> Result<SignalQuery, QueryError> {
    let from = parse_canonical_u64(&parameters.from)?;
    let to = parse_canonical_u64(&parameters.to)?;
    let buckets = parse_canonical_u32(&parameters.max_time_buckets)?;
    let metric = match parameters.metric.as_str() {
        "i" => Metric::I,
        "q" => Metric::Q,
        "amplitude" => Metric::Amplitude,
        "phase" => Metric::Phase,
        _ => return Err(invalid_query()),
    };
    let selection =
        SignalSelection::try_new(&parameters.session, &parameters.sensor, &parameters.link)?;
    let mut builder = SignalQuery::builder(
        selection,
        SignalRange::try_new(SessionTime::from_nanos(from), SessionTime::from_nanos(to))?,
        metric,
    )
    .max_time_buckets(buckets);
    if let Some(profile) = parameters.profile {
        builder = builder.profile(&profile);
    }
    if let Some(path) = parameters.path {
        builder = builder.path(parse_path(&path)?);
    }
    builder.build()
}

fn parse_canonical_u64(value: &str) -> Result<u64, QueryError> {
    if value.is_empty()
        || value.len() > MAX_U64_DECIMAL_DIGITS
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid_query());
    }
    value.parse().map_err(|_| invalid_query())
}

fn parse_canonical_u32(value: &str) -> Result<u32, QueryError> {
    u32::try_from(parse_canonical_u64(value)?).map_err(|_| invalid_query())
}

fn parse_canonical_u16(value: &str) -> Result<u16, QueryError> {
    u16::try_from(parse_canonical_u64(value)?).map_err(|_| invalid_query())
}

fn parse_path(value: &str) -> Result<SignalPath, QueryError> {
    if let Some(ordinal) = value.strip_prefix("raw_path_ordinal:") {
        return Ok(SignalPath::RawPathOrdinal { ordinal: parse_canonical_u16(ordinal)? });
    }
    let rest = value.strip_prefix("tx_rx:").ok_or_else(invalid_query)?;
    let mut parts = rest.split(':');
    let tx_stream = parse_canonical_u16(parts.next().ok_or_else(invalid_query)?)?;
    let rx_chain = parse_canonical_u16(parts.next().ok_or_else(invalid_query)?)?;
    if parts.next().is_some() {
        return Err(invalid_query());
    }
    Ok(SignalPath::TxRx { tx_stream, rx_chain })
}

fn invalid_query() -> QueryError {
    QueryError::invalid_request("invalid signal query")
}

pub(super) fn invalid_request_response(message: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, Json(ErrorEnvelope::invalid_request(message))).into_response()
}

pub(super) fn projection_failure_response() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorEnvelope::projection_failed())).into_response()
}

pub(super) async fn run_query<T, F>(control: &RuntimeControl, query: F) -> Result<T, ()>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, QueryError> + Send + 'static,
{
    let worker_control = control.clone();
    match tokio::task::spawn_blocking(move || {
        match std::panic::catch_unwind(AssertUnwindSafe(query)) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => {
                if !worker_control.is_stopping() {
                    worker_control.fail(error.into());
                }
                Err(())
            }
            Err(_) => {
                worker_control.fail(RuntimeError::new(RuntimeErrorKind::TaskPanicked("query")));
                Err(())
            }
        }
    })
    .await
    {
        Ok(result) => result,
        Err(error) => {
            task_failure(control, error);
            Err(())
        }
    }
}

fn task_failure(control: &RuntimeControl, error: tokio::task::JoinError) {
    control.fail(RuntimeError::join("query", error));
}

pub(super) fn request_has_query_properties(request: &Request) -> bool {
    request.uri().query().is_some_and(|query| !query.is_empty())
}

pub(super) fn request_has_body(request: &Request) -> bool {
    request.headers().contains_key(header::TRANSFER_ENCODING)
        || request.headers().get_all(header::CONTENT_LENGTH).iter().any(|length| {
            length.to_str().ok().and_then(|length| length.parse::<u64>().ok()) != Some(0)
        })
}

#[cfg(test)]
mod tests {
    use std::task::Poll;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn query_panic_stops_the_host_after_the_http_waiter_is_cancelled() {
        let control = RuntimeControl::new();
        let mut stopped = control.shutdown.subscribe();
        let mut query = Box::pin(run_query(&control, || -> Result<(), QueryError> {
            std::thread::sleep(Duration::from_millis(50));
            panic!("test query panic after HTTP cancellation");
        }));
        assert!(matches!(futures_util::poll!(&mut query), Poll::Pending));
        drop(query);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !*stopped.borrow() {
                stopped.changed().await.expect("Host control remains available");
            }
        })
        .await
        .expect("cancelled query panic did not stop the Host");
        let error = control.take_fatal().expect("query panic retained as primary failure");
        assert_eq!(error.failure(), super::super::RuntimeFailure::Supervisor);
    }
}
