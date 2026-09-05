//! Public protocol and local transport behavior for the bounded model worker.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use whisper::model_worker::{
    Checkpoint, DispatchDecision, DispatchQueue, ExecutionClass, InputManifest, ModelRequest,
    ModelResponse, ModelRun, ModelRunId, NumericContract, RequestIdentity, ResponseStatus,
    WorkerClient, WorkerLimits,
};

fn request(id: &str, tensor: Vec<u8>) -> ModelRequest {
    let run_id: ModelRunId = "run-1".parse().unwrap();
    let checkpoint = Checkpoint::new(run_id.clone(), 7, b"checkpoint-v1".to_vec());
    let identity = RequestIdentity::new(
        run_id.clone(),
        7,
        id.parse().unwrap(),
        250_000_000,
        checkpoint.digest(),
    );
    let numeric = NumericContract::new(
        ExecutionClass::CpuBaseline,
        true,
        0.0,
        0.0,
        "rust-test-f32".to_owned(),
    )
    .unwrap();
    let run =
        ModelRun::builder(run_id.clone(), b"deterministic-test-weights".to_vec(), vec![8], numeric)
            .algorithm("deterministic-double-v1")
            .preprocessing("f32-le-v1")
            .normalization("identity-v1")
            .input_semantics("qualified-rf-test-values-v1")
            .output_semantics("candidate-potentials-f32-le-v1")
            .label_semantics("joint-state-test-v1")
            .calibration_policy("frozen-references-v1")
            .tolerance_policy("bitwise-test-only-v1")
            .fusion_policy("test-identity-v1")
            .state_format("test-state-v1")
            .output_shape(vec![2])
            .build()
            .unwrap();
    let manifest = InputManifest::builder(
        b"frozen-input-manifest-v1".to_vec(),
        run_id,
        7,
        250_000_000,
        checkpoint.digest(),
    )
    .preprocessing("f32-le-v1")
    .input_semantics("qualified-rf-test-values-v1")
    .shape(vec![tensor.len() as u32 / 4])
    .tensor(tensor)
    .source_count(2)
    .clock_domain_count(2)
    .build()
    .unwrap();
    ModelRequest::new(identity, u64::MAX, run, manifest, checkpoint)
}

#[test]
fn codec_preserves_frozen_request_identity_and_bytes() {
    let limits = WorkerLimits::default();
    let request = request("request-1", [1.5_f32.to_le_bytes(), (-2.0_f32).to_le_bytes()].concat());
    let frame = request.encode(&limits).unwrap();
    let decoded = ModelRequest::decode(&frame, &limits).unwrap();
    assert_eq!(decoded, request);
    assert_eq!(&frame[..4], b"WMW1");
}

#[test]
fn codec_rejects_tensor_over_limit_before_transport() {
    let limits = WorkerLimits { max_tensor_bytes: 4, ..WorkerLimits::default() };
    let error = request("request-1", vec![0; 8]).encode(&limits).unwrap_err();
    assert!(error.to_string().contains("tensor"));
}

#[test]
fn dispatch_queue_keeps_one_inflight_and_only_latest_pending_context() {
    let limits = WorkerLimits::default();
    let mut queue = DispatchQueue::new(limits);
    let first = request("request-1", vec![0; 4]);
    let second = request("request-2", vec![0; 4]);
    let third = request("request-3", vec![0; 4]);

    assert!(matches!(queue.submit(first).unwrap(), DispatchDecision::Dispatch(_)));
    assert_eq!(queue.submit(second).unwrap(), DispatchDecision::Pending);
    assert_eq!(
        queue.submit(third).unwrap(),
        DispatchDecision::PendingReplaced { replaced_request_id: "request-2".parse().unwrap() }
    );
    let next = queue.complete("request-1".parse().unwrap()).unwrap().unwrap();
    assert_eq!(next.identity().request_id().as_str(), "request-3");
    assert!(queue.complete("request-3".parse().unwrap()).unwrap().is_none());
}

#[test]
fn local_client_sends_and_receives_one_bounded_frame() {
    let temporary =
        std::env::temp_dir().join(format!("whisper-worker-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&temporary);
    let listener = UnixListener::bind(&temporary).unwrap();
    let response = ModelResponse::failure(
        request("request-1", vec![0; 4]).identity().clone(),
        ResponseStatus::GpuOom,
        "simulated allocation failure",
    );
    let response_frame = response.encode(&WorkerLimits::default()).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut header = [0; 8];
        stream.read_exact(&mut header).unwrap();
        let length = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        assert_eq!(&header[..4], b"WMW1");
        stream.write_all(&response_frame).unwrap();
    });
    let client = WorkerClient::new(WorkerLimits::default(), Duration::from_secs(1));
    let received = client.execute(&temporary, &request("request-1", vec![0; 4])).unwrap();
    assert_eq!(received.status(), ResponseStatus::GpuOom);
    server.join().unwrap();
    std::fs::remove_file(temporary).unwrap();
}

#[test]
fn rust_client_interoperates_with_python_worker() {
    let temporary = std::path::PathBuf::from(format!("/tmp/ww-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&temporary);
    let script = r#"
import socket, sys
from model_worker.worker import DeterministicTestOperator, Limits, Worker, read_frame
path = sys.argv[1]
worker = Worker(DeterministicTestOperator(), Limits(), now_ns=lambda: 1)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
    listener.bind(path)
    listener.listen(1)
    connection, _ = listener.accept()
    with connection:
        connection.sendall(worker.handle_frame(read_frame(connection, Limits())))
"#;
    let child = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(&temporary)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if temporary.exists() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(temporary.exists(), "Python worker did not create its socket");
    let model_request =
        request("python-request-1", [1.5_f32.to_le_bytes(), (-2.0_f32).to_le_bytes()].concat());
    let response = WorkerClient::new(WorkerLimits::default(), Duration::from_secs(2))
        .execute(&temporary, &model_request)
        .unwrap();
    assert_eq!(response.status(), ResponseStatus::Success);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    std::fs::remove_file(temporary).unwrap();
}

#[test]
fn decode_rechecks_identifier_and_numeric_invariants() {
    let limits = WorkerLimits::default();
    let frame = request("request-1", vec![0; 4]).encode(&limits).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&frame[8..]).unwrap();
    value["identity"]["request_id"] = serde_json::Value::String(String::new());
    let payload = serde_json::to_vec(&value).unwrap();
    let mut invalid = b"WMW1".to_vec();
    invalid.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    invalid.extend_from_slice(&payload);
    assert!(ModelRequest::decode(&invalid, &limits).is_err());

    let mut value: serde_json::Value = serde_json::from_slice(&frame[8..]).unwrap();
    value["model_run"]["execution"]["environment"] = serde_json::Value::String(String::new());
    let payload = serde_json::to_vec(&value).unwrap();
    let mut invalid = b"WMW1".to_vec();
    invalid.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    invalid.extend_from_slice(&payload);
    assert!(ModelRequest::decode(&invalid, &limits).is_err());
}
