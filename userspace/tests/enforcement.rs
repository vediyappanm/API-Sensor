//! Startup enforcement, exercised on the real binary.
//!
//! Each case runs `api-sec-sensor --check-config` as a subprocess with a clean environment and
//! asserts the exit status and, for rejections, the reason printed. `--check-config` runs the
//! same checks as a normal start and exits before any BPF work, so no root is needed.

use std::process::{Command, Output};

const PII_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn run(ingest: &str, namespaces: Option<&str>, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_api-sec-sensor"));
    cmd.env_clear()
        .env("API_KEY", "test-key")
        .env("PII_HASH_KEY", PII_KEY)
        .args(["--check-config", "--bpf=/nonexistent.bpf.o", &format!("--ingest={ingest}")]);
    if let Some(ns) = namespaces {
        cmd.arg(format!("--only-namespaces={ns}"));
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run the sensor binary")
}

fn assert_rejected(out: &Output, reason: &str) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "expected rejection, got success. stderr: {stderr}");
    assert!(stderr.contains(reason), "rejection reason {reason:?} missing from: {stderr}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("configuration valid"));
}

fn assert_accepted(out: &Output) {
    assert!(
        out.status.success(),
        "expected acceptance, got {:?}. stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("configuration valid"));
}

#[test]
fn http_ingest_is_rejected_without_opt_in() {
    assert_rejected(&run("http://ingest:8080/v1/events", Some("apps"), &[]), "APISEC_ALLOW_HTTP");
}

#[test]
fn http_opt_in_set_to_false_does_not_allow_plaintext() {
    let out = run("http://ingest:8080/v1/events", Some("apps"), &[("APISEC_ALLOW_HTTP", "false")]);
    assert_rejected(&out, "APISEC_ALLOW_HTTP");
}

#[test]
fn http_ingest_is_accepted_with_explicit_opt_in() {
    assert_accepted(&run("http://ingest:8080/v1/events", Some("apps"), &[("APISEC_ALLOW_HTTP", "true")]));
}

#[test]
fn https_ingest_with_a_namespace_scope_is_accepted() {
    assert_accepted(&run("https://ingest.example.com/v1/events", Some("apps,payments"), &[]));
}

#[test]
fn capture_all_is_rejected_without_opt_in() {
    assert_rejected(&run("https://ingest.example.com/v1/events", None, &[]), "APISEC_ALLOW_CAPTURE_ALL");
}

#[test]
fn capture_all_is_accepted_with_explicit_opt_in() {
    assert_accepted(&run("https://ingest.example.com/v1/events", None, &[("APISEC_ALLOW_CAPTURE_ALL", "true")]));
}

#[test]
fn an_unrecognised_opt_in_value_is_a_configuration_error() {
    let out = run("https://ingest.example.com/v1/events", None, &[("APISEC_ALLOW_CAPTURE_ALL", "maybe")]);
    assert_rejected(&out, "APISEC_ALLOW_CAPTURE_ALL must be true or false");
}

#[test]
fn an_export_byte_budget_too_small_for_one_event_is_rejected() {
    let https = "https://ingest.example.com/v1/events";
    assert_rejected(&run(https, Some("apps"), &[("MAX_BATCH_BYTES", "1000")]), "--max-batch-bytes must be at least");
    assert_rejected(&run(https, Some("apps"), &[("MAX_QUEUE_BYTES", "0")]), "--max-queue-bytes must be at least");
    assert_accepted(&run(https, Some("apps"), &[("MAX_BATCH_BYTES", "65536"), ("MAX_QUEUE_BYTES", "200000")]));
}

#[test]
fn a_missing_pii_key_is_rejected() {
    let out = Command::new(env!("CARGO_BIN_EXE_api-sec-sensor"))
        .env_clear()
        .env("API_KEY", "test-key")
        .args(["--check-config", "--bpf=/x", "--ingest=https://i/v1/events", "--only-namespaces=apps"])
        .output()
        .unwrap();
    assert_rejected(&out, "PII_HASH_KEY");
}
