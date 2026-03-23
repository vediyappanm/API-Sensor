use serde::Deserialize;
use std::path::Path;

/// File-based configuration (TOML).
///
/// Every field is optional — CLI flags override file values, file values
/// override compiled defaults.  Operators can drop a config file at
/// `/etc/api-sentinel/config.toml` (or any path via `--config`) to avoid
/// passing 15+ CLI flags in a DaemonSet manifest.
#[derive(Debug, Deserialize, Default)]
pub struct SensorConfig {
    #[serde(default)]
    pub sensor: SensorSection,
}

#[derive(Debug, Deserialize, Default)]
pub struct SensorSection {
    pub bpf: Option<String>,
    pub ingest: Option<String>,
    pub api_key: Option<String>,
    pub account_id: Option<u64>,
    pub batch_size: Option<usize>,
    pub role: Option<String>,
    pub tls_libs: Option<Vec<String>>,
    pub tls_provider: Option<String>,
    pub pid: Option<i32>,
    pub discover_libs: Option<bool>,
    pub go_tls: Option<bool>,
    pub max_buffer_bytes: Option<usize>,
    pub max_total_buffer_bytes: Option<usize>,
    pub metrics_port: Option<u16>,
    pub sample_default: Option<u8>,
    pub sample_health: Option<u8>,
}

/// Load configuration from a TOML file.  Returns `Default` if file does not exist.
pub fn load_config(path: &str) -> anyhow::Result<SensorConfig> {
    let p = Path::new(path);
    if !p.exists() {
        tracing::debug!(path = %path, "config file not found, using CLI defaults");
        return Ok(SensorConfig::default());
    }
    let contents = std::fs::read_to_string(p)?;
    let cfg: SensorConfig = toml::from_str(&contents)?;
    tracing::info!(path = %path, "loaded config file");
    Ok(cfg)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_config() {
        let toml_str = r#"
[sensor]
bpf = "/opt/sensor/http_trace.bpf.o"
ingest = "https://ingest.example.com/v1/events"
api_key = "secret-key"
account_id = 2000000
batch_size = 500
role = "client"
tls_libs = ["/usr/lib/libssl.so.3"]
tls_provider = "openssl"
pid = 12345
discover_libs = true
go_tls = true
max_buffer_bytes = 131072
max_total_buffer_bytes = 209715200
metrics_port = 9091
sample_default = 50
sample_health = 1
"#;
        let cfg: SensorConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg.sensor.account_id, Some(2000000));
        assert_eq!(cfg.sensor.batch_size, Some(500));
        assert_eq!(cfg.sensor.role.as_deref(), Some("client"));
        assert_eq!(cfg.sensor.pid, Some(12345));
        assert_eq!(cfg.sensor.metrics_port, Some(9091));
        assert_eq!(cfg.sensor.sample_default, Some(50));
        assert!(cfg.sensor.discover_libs.unwrap());
        assert!(cfg.sensor.go_tls.unwrap());
    }

    #[test]
    fn parse_empty_config() {
        let cfg: SensorConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.sensor.bpf, None);
        assert_eq!(cfg.sensor.ingest, None);
    }

    #[test]
    fn parse_partial_config() {
        let toml_str = r#"
[sensor]
ingest = "http://localhost:8080/events"
batch_size = 100
"#;
        let cfg: SensorConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(
            cfg.sensor.ingest.as_deref(),
            Some("http://localhost:8080/events")
        );
        assert_eq!(cfg.sensor.batch_size, Some(100));
        assert_eq!(cfg.sensor.bpf, None);
    }
}
