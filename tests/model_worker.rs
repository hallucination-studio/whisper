//! Public protocol and local transport behavior for the bounded model worker.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use whisper::model_worker::{
    Checkpoint, ContentDigest, DispatchDecision, DispatchQueue, ExecutionClass, InputManifest,
    MIN_FRAME_BYTES, ModelRequest, ModelResponse, ModelRun, ModelRunId, NumericContract,
    RequestIdentity, ResponseStatus, WorkerClient, WorkerLimits,
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

fn success_response_value(model_request: &ModelRequest) -> serde_json::Value {
    let request_value = serde_json::to_value(model_request).unwrap();
    let candidate = [1.0_f32.to_le_bytes(), 2.0_f32.to_le_bytes()].concat();
    let successor = b"successor".to_vec();
    let mut payload = candidate.clone();
    payload.extend_from_slice(&successor);
    serde_json::json!({
        "protocol_version": 1,
        "identity": request_value["identity"],
        "status": "success",
        "detail": "",
        "candidate_hex": candidate.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "successor_hex": successor.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "output_shape": [2],
        "input_tensor_digest": request_value["input_manifest"]["tensor_digest"],
        "output_numeric_digest": ContentDigest::of(&candidate),
        "return_payload_digest": ContentDigest::of(&payload),
        "numeric_qualification": request_value["model_run"]["execution"],
    })
}

fn frame_from_value(value: &serde_json::Value) -> Vec<u8> {
    let payload = serde_json::to_vec(value).unwrap();
    let mut frame = b"WMW1".to_vec();
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
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
fn codec_rejects_frame_limit_below_protocol_minimum() {
    let limits = WorkerLimits { max_frame_bytes: MIN_FRAME_BYTES - 1, ..WorkerLimits::default() };
    let error = request("request-1", vec![0; 4]).encode(&limits).unwrap_err();
    assert!(error.to_string().contains(&MIN_FRAME_BYTES.to_string()));
}

#[test]
fn rust_decodes_python_minimum_limit_fallback_as_a_complete_response() {
    let script = r#"
import sys
from model_worker.worker import DeterministicTestOperator, Limits, MIN_FRAME_BYTES, Worker
assert MIN_FRAME_BYTES == int(sys.argv[1])
limits = Limits(max_frame_bytes=MIN_FRAME_BYTES)
oversized = b"WMW1" + (MIN_FRAME_BYTES).to_bytes(4, "big")
sys.stdout.buffer.write(Worker(DeterministicTestOperator(), limits).handle_frame(oversized))
"#;
    let output = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(MIN_FRAME_BYTES.to_string())
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));

    let limits = WorkerLimits { max_frame_bytes: MIN_FRAME_BYTES, ..WorkerLimits::default() };
    let response = ModelResponse::decode(&output.stdout, &limits).unwrap();
    assert_eq!(response.status(), ResponseStatus::MalformedRequest);
    assert!(output.stdout.len() <= MIN_FRAME_BYTES);
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
    )
    .unwrap();
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
fn local_client_rejects_same_element_wrong_output_shape() {
    let temporary =
        std::env::temp_dir().join(format!("whisper-worker-shape-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&temporary);
    let listener = UnixListener::bind(&temporary).unwrap();
    let model_request = request("request-shape", vec![0; 4]);
    let mut response = success_response_value(&model_request);
    response["output_shape"] = serde_json::json!([1, 2]);
    let response_frame = frame_from_value(&response);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut header = [0; 8];
        stream.read_exact(&mut header).unwrap();
        let length = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        stream.write_all(&response_frame).unwrap();
    });

    let error = WorkerClient::new(WorkerLimits::default(), Duration::from_secs(1))
        .execute(&temporary, &model_request)
        .unwrap_err();
    assert!(error.to_string().contains("shape"));
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
    let tensor = [1.5_f32.to_le_bytes(), (-2.0_f32).to_le_bytes()].concat();
    let model_request = request("python-request-1", tensor.clone());
    let expected_identity = model_request.identity().clone();
    let response = WorkerClient::new(WorkerLimits::default(), Duration::from_secs(2))
        .execute(&temporary, &model_request)
        .unwrap();
    assert_eq!(response.status(), ResponseStatus::Success);
    assert_eq!(response.identity(), &expected_identity);
    assert_eq!(response.detail(), "");
    let expected_candidate = [3.0_f32.to_le_bytes(), (-4.0_f32).to_le_bytes()].concat();
    assert_eq!(response.candidate_bytes(), expected_candidate);
    let expected_successor = Sha256::digest(
        [b"successor-v1".as_slice(), b"checkpoint-v1".as_slice(), tensor.as_slice()].concat(),
    );
    assert_eq!(response.successor_checkpoint(), expected_successor.as_slice());
    assert_eq!(response.output_shape(), [2]);
    assert_eq!(response.input_tensor_digest(), Some(ContentDigest::of(&tensor)));
    assert_eq!(response.output_numeric_digest(), Some(ContentDigest::of(&expected_candidate)));
    let expected_payload = [expected_candidate.as_slice(), expected_successor.as_slice()].concat();
    assert_eq!(response.return_payload_digest(), Some(ContentDigest::of(&expected_payload)));
    let expected_qualification = NumericContract::new(
        ExecutionClass::CpuBaseline,
        true,
        0.0,
        0.0,
        "rust-test-f32".to_owned(),
    )
    .unwrap();
    assert_eq!(response.numeric_qualification(), Some(&expected_qualification));
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

#[test]
fn public_deserialization_preserves_identifier_and_numeric_invariants() {
    assert!(serde_json::from_str::<ModelRunId>("\"\"").is_err());
    assert!(serde_json::from_str::<whisper::model_worker::ModelRequestId>("\"\"").is_err());
    let uppercase_digest =
        serde_json::to_string(&ContentDigest::of(b"canonical-hex")).unwrap().to_uppercase();
    assert!(serde_json::from_str::<ContentDigest>(&uppercase_digest).is_err());

    for invalid in [
        r#"{"class":"cpu_baseline","deterministic_algorithms":true,"absolute_tolerance":-1.0,"relative_tolerance":0.0,"environment":"rust-test-f32"}"#,
        r#"{"class":"cpu_baseline","deterministic_algorithms":true,"absolute_tolerance":0.0,"relative_tolerance":0.0,"environment":""}"#,
    ] {
        assert!(serde_json::from_str::<NumericContract>(invalid).is_err());
    }
}

#[test]
fn model_run_deserialization_rejects_invalid_schema_digest_text_and_shapes() {
    let value = serde_json::to_value(request("request-1", vec![0; 4])).unwrap();
    let model_run = value["model_run"].clone();
    for (field, invalid) in [
        ("schema_version", serde_json::json!(2)),
        ("weights_digest", serde_json::json!("00".repeat(32))),
        ("algorithm", serde_json::json!("")),
        ("max_shape", serde_json::json!([])),
        ("output_shape", serde_json::json!([0])),
        (
            "weights_hex",
            serde_json::json!(model_run["weights_hex"].as_str().unwrap().to_uppercase()),
        ),
    ] {
        let mut mutated = model_run.clone();
        mutated[field] = invalid;
        assert!(
            serde_json::from_value::<ModelRun>(mutated).is_err(),
            "accepted invalid model-run {field}"
        );
    }
}

#[test]
fn input_manifest_deserialization_rejects_invalid_schema_digests_text_and_shape() {
    let value = serde_json::to_value(request("request-1", vec![0; 4])).unwrap();
    let manifest = value["input_manifest"].clone();
    for (field, invalid) in [
        ("schema_version", serde_json::json!(2)),
        ("manifest_digest", serde_json::json!("00".repeat(32))),
        ("tensor_digest", serde_json::json!("00".repeat(32))),
        ("preprocessing", serde_json::json!("")),
        ("shape", serde_json::json!([2])),
        (
            "manifest_hex",
            serde_json::json!(manifest["manifest_hex"].as_str().unwrap().to_uppercase()),
        ),
        ("tensor_hex", serde_json::json!("0A000000")),
    ] {
        let mut mutated = manifest.clone();
        mutated[field] = invalid;
        assert!(
            serde_json::from_value::<InputManifest>(mutated).is_err(),
            "accepted invalid input-manifest {field}"
        );
    }
}

#[test]
fn checkpoint_deserialization_rejects_digest_mutation() {
    let value = serde_json::to_value(request("request-1", vec![0; 4])).unwrap();
    let mut checkpoint = value["checkpoint"].clone();
    checkpoint["digest"] = serde_json::json!("00".repeat(32));
    assert!(serde_json::from_value::<Checkpoint>(checkpoint).is_err());

    let mut checkpoint = value["checkpoint"].clone();
    checkpoint["bytes_hex"] =
        serde_json::json!(checkpoint["bytes_hex"].as_str().unwrap().to_uppercase());
    assert!(serde_json::from_value::<Checkpoint>(checkpoint).is_err());
}

#[test]
fn model_request_deserialization_rejects_protocol_and_cross_binding_mutations() {
    let request = serde_json::to_value(request("request-1", vec![0; 4])).unwrap();
    let mut invalid_protocol = request.clone();
    invalid_protocol["protocol_version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<ModelRequest>(invalid_protocol).is_err());

    for path in ["run_id", "epoch", "cutoff_ns", "predecessor_digest"] {
        let mut mutated = request.clone();
        mutated["identity"][path] = match path {
            "run_id" => serde_json::json!("different-run"),
            "epoch" => serde_json::json!(8),
            "cutoff_ns" => serde_json::json!(250_000_001_u64),
            "predecessor_digest" => serde_json::json!("00".repeat(32)),
            _ => unreachable!(),
        };
        assert!(
            serde_json::from_value::<ModelRequest>(mutated).is_err(),
            "accepted invalid request {path} binding"
        );
    }

    let mut mismatched_semantics = request;
    mismatched_semantics["input_manifest"]["preprocessing"] = serde_json::json!("other-v1");
    assert!(serde_json::from_value::<ModelRequest>(mismatched_semantics).is_err());
}

#[test]
fn model_response_deserialization_rejects_invalid_success_and_failure_invariants() {
    let model_request = request("request-1", vec![0; 4]);
    let mut failure = serde_json::to_value(
        ModelResponse::failure(
            model_request.identity().clone(),
            ResponseStatus::OperatorFailure,
            "operator failed",
        )
        .unwrap(),
    )
    .unwrap();

    let mut invalid_protocol = failure.clone();
    invalid_protocol["protocol_version"] = serde_json::json!(2);
    assert!(serde_json::from_value::<ModelResponse>(invalid_protocol).is_err());

    failure["candidate_hex"] = serde_json::json!("00000000");
    assert!(serde_json::from_value::<ModelResponse>(failure).is_err());

    let mut success = success_response_value(&model_request);
    assert!(serde_json::from_value::<ModelResponse>(success.clone()).is_ok());
    success["output_numeric_digest"] = serde_json::json!("00".repeat(32));
    assert!(serde_json::from_value::<ModelResponse>(success).is_err());

    let mut uppercase = success_response_value(&model_request);
    uppercase["candidate_hex"] =
        serde_json::json!(uppercase["candidate_hex"].as_str().unwrap().to_uppercase());
    assert!(serde_json::from_value::<ModelResponse>(uppercase).is_err());
}

#[test]
fn failure_response_constructor_rejects_success_and_overlong_utf8_detail() {
    let identity = request("request-1", vec![0; 4]).identity().clone();
    assert!(ModelResponse::failure(identity.clone(), ResponseStatus::Success, "").is_err());

    let overlong_utf8_detail = "界".repeat(86);
    assert_eq!(overlong_utf8_detail.len(), 258);
    assert!(
        ModelResponse::failure(identity, ResponseStatus::OperatorFailure, overlong_utf8_detail,)
            .is_err()
    );
}
