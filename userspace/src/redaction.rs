use crate::types::AnomalyFeatures;
use hmac::{Hmac, Mac};
use regex::Regex;
use sha2::Sha256;
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// PII Redaction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum PiiType {
    Email,
    CreditCard,
    Ssn,
    Phone,
    Jwt,
    BearerToken,
    PrivateKey,
    AwsKey,
    GcpToken,
    IndianPan,
    Aadhaar,
    TelegramBotToken,
    SlackToken,
    GithubToken,
    StripeKey,
    GoogleApiKey,
    GenericApiKey,
    HighEntropySecret,
}

#[allow(dead_code)]
pub struct PiiDetection {
    pub pii_type: PiiType,
    pub token: String,
}

static PII_PATTERNS: OnceLock<Vec<(PiiType, Regex)>> = OnceLock::new();

static PII_HASH_KEY: OnceLock<Vec<u8>> = OnceLock::new();

/// Initialize the PII hash key from `PII_HASH_KEY` env var.
/// In production (`SENSOR_ENV=production`), the sensor refuses to start without an explicit key.
/// In dev/test, a deterministic fallback is used with a loud warning.
fn pii_hash_key() -> &'static [u8] {
    PII_HASH_KEY.get_or_init(|| {
        if let Ok(hex) = std::env::var("PII_HASH_KEY") {
            if hex.len() == 64 {
                let bytes: Option<Vec<u8>> = (0..32)
                    .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
                    .collect();
                if let Some(key) = bytes {
                    return key;
                }
            }
            panic!(
                "FATAL: PII_HASH_KEY must be exactly 64 hex chars (32 bytes). Got {} chars.",
                hex.len()
            );
        }

        let is_production = std::env::var("SENSOR_ENV")
            .map(|v| v.eq_ignore_ascii_case("production") || v.eq_ignore_ascii_case("prod"))
            .unwrap_or(false);

        if is_production {
            panic!(
                "FATAL: PII_HASH_KEY env var is required in production. \
                 Set a unique 64 hex char (32 byte) key per deployment. \
                 PII tokens are correlatable across deployments without a unique key."
            );
        }

        tracing::warn!(
            "PII_HASH_KEY not set — using deterministic dev key. \
             PII tokens are correlatable. Set PII_HASH_KEY (64 hex chars) for production."
        );
        // Dev-only fallback key — never used in production
        b"apisec_dev_key_not_for_prod_use!".to_vec()
    })
}

pub fn pii_token(pii_type: &PiiType, original: &str) -> String {
    let key = pii_hash_key();
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(original.as_bytes());
    let result = mac.finalize().into_bytes();
    let hash = u64::from_le_bytes(result[..8].try_into().unwrap());
    match pii_type {
        PiiType::Email => format!("PII_EMAIL_{hash:016x}"),
        PiiType::CreditCard => format!("PII_CARD_{hash:016x}"),
        PiiType::Ssn => format!("PII_SSN_{hash:016x}"),
        PiiType::Phone => format!("PII_PHONE_{hash:016x}"),
        PiiType::Jwt => format!("PII_JWT_{hash:016x}"),
        PiiType::BearerToken => format!("PII_TOKEN_{hash:016x}"),
        PiiType::PrivateKey => "PII_PRIVATE_KEY_REDACTED".to_string(),
        PiiType::AwsKey => format!("PII_AWSKEY_{hash:016x}"),
        PiiType::GcpToken => format!("PII_GCPTOKEN_{hash:016x}"),
        PiiType::IndianPan => format!("PII_PAN_{hash:016x}"),
        PiiType::Aadhaar => format!("PII_AADHAAR_{hash:016x}"),
        PiiType::TelegramBotToken => format!("PII_TGBOT_{hash:016x}"),
        PiiType::SlackToken => format!("PII_SLACK_{hash:016x}"),
        PiiType::GithubToken => format!("PII_GHTOKEN_{hash:016x}"),
        PiiType::StripeKey => format!("PII_STRIPE_{hash:016x}"),
        PiiType::GoogleApiKey => format!("PII_GOOGLEKEY_{hash:016x}"),
        PiiType::GenericApiKey => format!("PII_APIKEY_{hash:016x}"),
        PiiType::HighEntropySecret => format!("PII_SECRET_{hash:016x}"),
    }
}

fn init_pii_patterns() -> Vec<(PiiType, Regex)> {
    vec![
        (
            PiiType::Jwt,
            Regex::new(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}").unwrap(),
        ),
        (
            PiiType::BearerToken,
            Regex::new(r"(?i)Bearer\s+([A-Za-z0-9\-._~+/]+=*)").unwrap(),
        ),
        // Telegram bot token: <bot_id>:<auth_hash> (e.g. 123456789:AAH...).
        // This is the format that leaked unredacted into a request path.
        (
            // No leading \b: the bot id is often glued to a path segment
            // (e.g. `/bot<id>:<hash>`), so there is no word boundary before it.
            PiiType::TelegramBotToken,
            Regex::new(r"\d{6,12}:[A-Za-z0-9_-]{30,}\b").unwrap(),
        ),
        // Slack tokens: xoxb-/xoxp-/xoxa-/xoxr-/xoxs-...
        (
            PiiType::SlackToken,
            Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap(),
        ),
        // GitHub tokens: ghp_/gho_/ghu_/ghs_/ghr_ + 36+ base62 chars
        (
            PiiType::GithubToken,
            Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b").unwrap(),
        ),
        // Stripe secret/restricted/publishable keys
        (
            PiiType::StripeKey,
            Regex::new(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b").unwrap(),
        ),
        // Google API key: AIza + 35 chars
        (
            PiiType::GoogleApiKey,
            Regex::new(r"\bAIza[A-Za-z0-9_-]{35}\b").unwrap(),
        ),
        (
            PiiType::Email,
            Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
        ),
        // Credit card formats — format check, NOT Luhn validated
        (
            PiiType::CreditCard,
            Regex::new(r"\b(?:4[0-9]{15}|5[1-5][0-9]{14}|3[47][0-9]{13}|6011[0-9]{12})\b").unwrap(),
        ),
        (PiiType::Ssn, Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()),
        (
            PiiType::PrivateKey,
            Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap(),
        ),
        (
            PiiType::Phone,
            Regex::new(r"\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s][2-9]\d{2}[-.\s]\d{4}\b").unwrap(),
        ),
        // AWS Access Key ID (starts with AKIA, 20 chars)
        (PiiType::AwsKey, Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
        // GCP OAuth token
        (
            PiiType::GcpToken,
            Regex::new(r"ya29\.[A-Za-z0-9_-]{20,}").unwrap(),
        ),
        // Indian PAN — 5th char encodes holder type (P=Person, C=Company, etc.)
        // Require PAN: or pan: prefix, or assignment context to avoid false positives
        (
            PiiType::IndianPan,
            Regex::new(r"(?i)(?:pan[:\s=]+)[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]").unwrap(),
        ),
        // Aadhaar — 12 digits starting with 2-9 (UIDAI spec), space/dash separated as 4-4-4
        // Require aadhaar/uid prefix or separator pattern to avoid matching arbitrary 12-digit numbers
        (
            PiiType::Aadhaar,
            Regex::new(r"(?i)(?:aadhaar|uid|aadhar)[:\s=]+[2-9]\d{3}[\s-]\d{4}[\s-]\d{4}").unwrap(),
        ),
        // Generic secret carried in a `key=value` / `key:value` context. The
        // capture group isolates the value so only the secret is redacted and
        // the field name (e.g. `api_key=`) is preserved. Kept LAST so the
        // specific provider patterns above win on any overlap.
        (
            PiiType::GenericApiKey,
            Regex::new(
                r#"(?i)(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|secret[_-]?key|client[_-]?secret)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,})"#,
            )
            .unwrap(),
        ),
    ]
}

// `sum % 10 == 0` is kept rather than `sum.is_multiple_of(10)`: the Docker build
// pins rust 1.85, and u32::is_multiple_of was only stabilized in 1.87.
#[allow(clippy::manual_is_multiple_of)]
fn luhn_check(digits: &str) -> bool {
    let digits: Vec<u32> = digits
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut n = d;
        if double {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        double = !double;
    }
    sum % 10 == 0
}

/// Candidate runs for the generic high-entropy secret catch-all: contiguous
/// base64/url-safe/hex token characters, 24–256 long.
static SECRET_CANDIDATE_RE: OnceLock<Regex> = OnceLock::new();

fn secret_candidate_re() -> &'static Regex {
    // base64url *body* chars only — deliberately excludes structural separators
    // (`/ = . + : ? &`) so a candidate is one opaque token, not a field name,
    // path, or an already-redacted `PII_*` run glued to its neighbours.
    SECRET_CANDIDATE_RE.get_or_init(|| Regex::new(r"[A-Za-z0-9_-]{24,256}").unwrap())
}

/// Conservative heuristic for "this opaque token is probably a credential".
/// Deliberately tuned for LOW false positives — the named patterns above catch
/// known formats; this is the safety net for unknown ones (the failure mode
/// that originally leaked a Telegram bot token). Excludes our own `PII_*`
/// tokens, pure-hex digests (git SHAs / etags / checksums), and UUIDs, which
/// are high-entropy but rarely secret and would be noisy to redact.
fn looks_like_secret(t: &str) -> bool {
    let len = t.len();
    if !(24..=256).contains(&len) {
        return false;
    }
    if t.contains("PII_") {
        return false; // overlaps an already-redacted token; don't re-redact
    }
    let has_lower = t.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = t.bytes().any(|b| b.is_ascii_uppercase());
    let has_digit = t.bytes().any(|b| b.is_ascii_digit());
    // Require a letter and (a digit or mixed case) — excludes pure-alpha slugs.
    if !((has_lower || has_upper) && (has_digit || (has_lower && has_upper))) {
        return false;
    }
    // Pure hex → digest/checksum, not a secret. Exclude.
    if t.bytes()
        .all(|b| b.is_ascii_hexdigit() || b == b'-' || b == b'_')
    {
        // hex (optionally with separators): SHA/UUID/etag — skip.
        if t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        if is_uuid(t) {
            return false;
        }
    }
    shannon_entropy(t) >= 4.0
}

/// UUID v1–v5 canonical form: 8-4-4-4-12 hex.
fn is_uuid(t: &str) -> bool {
    let b = t.as_bytes();
    if b.len() != 36 {
        return false;
    }
    b.iter().enumerate().all(|(i, &c)| {
        if matches!(i, 8 | 13 | 18 | 23) {
            c == b'-'
        } else {
            c.is_ascii_hexdigit()
        }
    })
}

/// Final pass of [`redact_pii`]: replace freestanding high-entropy tokens that
/// look like credentials but matched no named pattern.
fn redact_high_entropy(text: &str) -> String {
    let re = secret_candidate_re();
    let snapshot = text.to_string();
    let ranges: Vec<(usize, usize, String)> = re
        .find_iter(&snapshot)
        .filter(|m| looks_like_secret(m.as_str()))
        .map(|m| {
            (
                m.start(),
                m.end(),
                pii_token(&PiiType::HighEntropySecret, m.as_str()),
            )
        })
        .collect();
    let mut result = snapshot;
    for (start, end, token) in ranges.into_iter().rev() {
        result.replace_range(start..end, &token);
    }
    result
}

pub fn redact_pii(text: &str) -> String {
    let patterns = PII_PATTERNS.get_or_init(init_pii_patterns);
    let mut result = text.to_string();
    for (pii_type, pattern) in patterns {
        // Patterns with an explicit capture group redact only group 1 (the
        // secret value), preserving surrounding context like `api_key=` or the
        // `Bearer ` scheme. Patterns without a group redact the whole match.
        let group_only = pattern.captures_len() > 1;
        // Collect all matches first (to avoid borrow conflict during replacement)
        let snapshot = result.clone();
        let ranges: Vec<(usize, usize, String)> = pattern
            .captures_iter(&snapshot)
            .filter_map(|caps| {
                let full = caps.get(0)?;
                // Apply Luhn validation for credit card matches (whole number)
                if *pii_type == PiiType::CreditCard && !luhn_check(full.as_str()) {
                    return None;
                }
                let target = if group_only { caps.get(1)? } else { full };
                Some((
                    target.start(),
                    target.end(),
                    pii_token(pii_type, target.as_str()),
                ))
            })
            .collect();
        // Replace in reverse order to preserve offsets
        for (start, end, token) in ranges.into_iter().rev() {
            result.replace_range(start..end, &token);
        }
    }
    // Catch-all: redact any remaining high-entropy, credential-shaped tokens
    // that matched no named pattern above (defense against unknown secret
    // formats). Runs last so named tokens (already `PII_*`) are skipped.
    redact_high_entropy(&result)
}

// ---------------------------------------------------------------------------
// Anomaly feature extraction
//
// Computes the lightweight `AnomalyFeatures` vector attached to every API
// traffic event. These are cheap, deterministic signals derived from the raw
// (pre-redaction) request — they feed downstream ML/anomaly scoring and double
// as coarse injection flags (SQLi / XSS / path traversal).
// ---------------------------------------------------------------------------

static SQLI_RE: OnceLock<Regex> = OnceLock::new();
static XSS_RE: OnceLock<Regex> = OnceLock::new();

fn sqli_re() -> &'static Regex {
    SQLI_RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(\bunion\b\s+\bselect\b|\bselect\b\s+.{0,80}?\bfrom\b|'\s*or\s+'?1'?\s*=\s*'?1|\bor\b\s+1\s*=\s*1\b|;\s*\b(?:drop|delete|insert|update|alter)\b|--\s|/\*.*\*/|\bxp_cmdshell\b|\bsleep\s*\(\s*\d|\bbenchmark\s*\(|\bwaitfor\s+delay\b)"#,
        )
        .unwrap()
    })
}

fn xss_re() -> &'static Regex {
    XSS_RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(<\s*script\b|<\s*/\s*script\s*>|javascript:|on(?:error|load|click|mouseover|focus)\s*=|<\s*iframe\b|<\s*svg\b|<\s*img\b[^>]*\bonerror|document\.cookie|\beval\s*\(|alert\s*\()"#,
        )
        .unwrap()
    })
}

/// Lightweight percent-decoder used for injection detection so that encoded
/// payloads (e.g. `%27%20OR%201=1`) are caught. Decodes valid `%XX` escapes,
/// leaves malformed ones intact. Returns `(decoded, had_any_encoding)`.
fn percent_decode(s: &str) -> (String, bool) {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut had_encoding = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                had_encoding = true;
                i += 3;
                continue;
            }
        }
        // A '+' in a query string also denotes an encoded space.
        if bytes[i] == b'+' {
            had_encoding = true;
        }
        out.push(bytes[i]);
        i += 1;
    }
    (String::from_utf8_lossy(&out).into_owned(), had_encoding)
}

/// Shannon entropy (bits/byte) of a string — high values flag obfuscated or
/// packed payloads. Returns 0.0 for empty input; range is [0, 8].
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f32;
    let mut entropy = 0.0f32;
    for &c in counts.iter() {
        if c > 0 {
            let p = c as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Bucket a byte count into a coarse 0–5 scale (log-ish): 0:<256, 1:<1K,
/// 2:<4K, 3:<16K, 4:<64K, 5:>=64K.
fn size_bucket(n: usize) -> u8 {
    match n {
        0..=255 => 0,
        256..=1023 => 1,
        1024..=4095 => 2,
        4096..=16383 => 3,
        16384..=65535 => 4,
        _ => 5,
    }
}

/// Derive the `AnomalyFeatures` vector from a raw request path (which may
/// include a `?query`) and an optional body. Computed on the *raw*, decoded
/// request so injection payloads and entropy reflect the wire content, not the
/// redacted form.
pub fn compute_anomaly_features(raw_path: &str, body: Option<&str>) -> AnomalyFeatures {
    let (base, query) = match raw_path.split_once('?') {
        Some((b, q)) => (b, q),
        None => (raw_path, ""),
    };

    let path_depth = base
        .split('/')
        .filter(|s| !s.is_empty())
        .count()
        .min(u8::MAX as usize) as u8;

    let query_param_count = if query.is_empty() {
        0
    } else {
        query
            .split('&')
            .filter(|s| !s.is_empty())
            .count()
            .min(u8::MAX as usize) as u8
    };

    let (decoded_path, enc_path) = percent_decode(raw_path);
    let (decoded_body, enc_body) = match body {
        Some(b) => percent_decode(b),
        None => (String::new(), false),
    };
    let has_encoded_chars = enc_path || enc_body;

    // Build the detection corpus from the decoded path/query plus body.
    let mut corpus = decoded_path.clone();
    if !decoded_body.is_empty() {
        corpus.push('\n');
        corpus.push_str(&decoded_body);
    }

    let has_sqli_pattern = sqli_re().is_match(&corpus);
    let has_xss_pattern = xss_re().is_match(&corpus);
    let has_path_traversal = decoded_path.contains("../")
        || decoded_path.contains("..\\")
        || decoded_body.contains("../")
        || decoded_body.contains("..\\");

    let total_size = raw_path.len() + body.map(|b| b.len()).unwrap_or(0);

    AnomalyFeatures {
        path_depth,
        query_param_count,
        has_encoded_chars,
        request_size_bucket: size_bucket(total_size),
        shannon_entropy: shannon_entropy(raw_path),
        has_sqli_pattern,
        has_xss_pattern,
        has_path_traversal,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pii_redact_email() {
        let input = "Contact us at user@example.com for support";
        let output = redact_pii(input);
        assert!(!output.contains("user@example.com"));
        assert!(output.contains("PII_EMAIL_"));
    }

    #[test]
    fn test_pii_redact_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let input = format!("Authorization: Bearer {}", jwt);
        let output = redact_pii(&input);
        assert!(!output.contains(jwt));
        // Either JWT or Bearer token pattern matched
        assert!(output.contains("PII_JWT_") || output.contains("PII_TOKEN_"));
    }

    #[test]
    fn test_pii_token_deterministic() {
        let email = "test@example.com";
        let t1 = pii_token(&PiiType::Email, email);
        let t2 = pii_token(&PiiType::Email, email);
        assert_eq!(t1, t2, "PII tokens must be deterministic");
        // Different values produce different tokens
        let t3 = pii_token(&PiiType::Email, "other@example.com");
        assert_ne!(t1, t3);
    }

    #[test]
    fn test_pii_redact_ssn() {
        let input = "SSN: 123-45-6789";
        let output = redact_pii(input);
        assert!(!output.contains("123-45-6789"));
        assert!(output.contains("PII_SSN_"));
    }

    #[test]
    fn test_pii_redact_private_key() {
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...";
        let output = redact_pii(input);
        assert!(output.contains("PII_PRIVATE_KEY_REDACTED"));
    }

    #[test]
    fn test_pii_redact_aws_key() {
        let input = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        let output = redact_pii(input);
        assert!(!output.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(output.contains("PII_AWSKEY_"));
    }

    #[test]
    fn test_pii_redact_gcp_token() {
        let input = "Authorization: Bearer ya29.a0ARrdaM8ABCDEFGHIJKLMNOPQRST";
        let output = redact_pii(input);
        assert!(!output.contains("ya29.a0ARrdaM8ABCDEFGHIJKLMNOPQRST"));
        assert!(output.contains("PII_GCPTOKEN_") || output.contains("PII_TOKEN_"));
    }

    #[test]
    fn test_pii_redact_indian_pan() {
        // PAN with context prefix — should be redacted
        let input = "PAN: ABCPD1234F";
        let output = redact_pii(input);
        assert!(!output.contains("ABCPD1234F"));
        assert!(output.contains("PII_PAN_"));
    }

    #[test]
    fn test_pii_no_false_positive_pan() {
        // Bare 10-char uppercase string without PAN context — should NOT be redacted
        let input = "Product code XYZAB1234C in stock";
        let output = redact_pii(input);
        assert_eq!(input, output);
    }

    #[test]
    fn test_pii_redact_aadhaar() {
        // Aadhaar with context prefix and valid first digit (2-9)
        let input = "Aadhaar: 2345 6789 0123";
        let output = redact_pii(input);
        assert!(!output.contains("2345 6789 0123"));
        assert!(output.contains("PII_AADHAAR_"));
    }

    #[test]
    fn test_pii_no_false_positive_aadhaar() {
        // Bare 12-digit number without Aadhaar context — should NOT be redacted
        let input = "Order #1234 5678 9012 confirmed";
        let output = redact_pii(input);
        assert_eq!(input, output);
    }

    #[test]
    fn test_luhn_check() {
        // Valid Visa test card
        assert!(super::luhn_check("4111111111111111"));
        // Invalid number
        assert!(!super::luhn_check("4111111111111112"));
        // Too short
        assert!(!super::luhn_check("123"));
    }

    #[test]
    fn test_pii_redact_telegram_bot_token_in_path() {
        // Reproduces the leak shape observed during e2e capture (a bot token in
        // a URL path). The token is SYNTHETIC and assembled at runtime so no
        // credential-shaped literal lands in source (push-protection / scanners).
        let token = format!(
            "{}:{}",
            "100000000", "AAFsyntheticTESTtokenValue0000000000zz"
        );
        let input = format!("/bot{token}/getUpdates");
        let output = redact_pii(&input);
        assert!(!output.contains(&token));
        assert!(output.contains("PII_TGBOT_"));
        // Surrounding path structure is preserved.
        assert!(output.starts_with("/bot"));
        assert!(output.ends_with("/getUpdates"));
    }

    #[test]
    fn test_pii_redact_slack_token() {
        // Assembled at runtime so the literal token never appears in source.
        let token = format!("xoxb-{}-{}", "111111111111", "ABCdefABCdefABCdef");
        let input = format!("token={token}");
        let output = redact_pii(&input);
        assert!(!output.contains(&token));
        assert!(output.contains("PII_SLACK_"));
    }

    #[test]
    fn test_pii_redact_github_token() {
        let input = "Authorization: ghp_1234567890abcdefABCDEF1234567890abcdef";
        let output = redact_pii(input);
        assert!(!output.contains("ghp_1234567890abcdefABCDEF1234567890abcdef"));
        assert!(output.contains("PII_GHTOKEN_"));
    }

    #[test]
    fn test_pii_redact_stripe_key() {
        // Assembled at runtime so the literal key never appears in source.
        let key = format!("sk_{}_{}", "live", "FAKEstripeKEYforTESTS0001");
        let output = redact_pii(&key);
        assert!(!output.contains(&key));
        assert!(output.contains("PII_STRIPE_"));
    }

    #[test]
    fn test_pii_redact_google_api_key() {
        let input = "key=AIzaSyA1234567890abcdefghijklmnopqrstuv";
        let output = redact_pii(input);
        assert!(!output.contains("AIzaSyA1234567890abcdefghijklmnopqrstuv"));
        assert!(output.contains("PII_GOOGLEKEY_"));
    }

    #[test]
    fn test_pii_redact_generic_api_key_preserves_field_name() {
        let input = "/v1/data?api_key=s3cr3tValue1234567890&page=2";
        let output = redact_pii(input);
        assert!(!output.contains("s3cr3tValue1234567890"));
        assert!(output.contains("PII_APIKEY_"));
        // Only the value is redacted; the field name and other params remain.
        assert!(output.contains("api_key="));
        assert!(output.contains("page=2"));
    }

    #[test]
    fn test_pii_no_false_positive_short_path_segment() {
        // Ordinary numeric/short path ids must not trip the new patterns.
        let input = "/users/12345/orders/678";
        let output = redact_pii(input);
        assert_eq!(input, output);
    }

    #[test]
    fn test_high_entropy_secret_redacted() {
        // An unknown-format, credential-shaped token (no named pattern) must
        // still be redacted by the catch-all.
        let input = "/callback?state=Zk9pX2qL3mWnB7vR8sT1uY4eC6dA0fG2hJ5kP";
        let output = redact_pii(input);
        assert!(!output.contains("Zk9pX2qL3mWnB7vR8sT1uY4eC6dA0fG2hJ5kP"));
        assert!(output.contains("PII_SECRET_"));
        // Surrounding structure preserved.
        assert!(output.starts_with("/callback?state="));
    }

    #[test]
    fn test_high_entropy_no_false_positive_uuid() {
        let input = "/orders/550e8400-e29b-41d4-a716-446655440000/items";
        assert_eq!(redact_pii(input), input);
    }

    #[test]
    fn test_high_entropy_no_false_positive_sha256() {
        // 64-char hex digest (e.g. content hash / git object) — must NOT redact.
        let input = "/blobs/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(redact_pii(input), input);
    }

    #[test]
    fn test_high_entropy_no_false_positive_normal_path() {
        let input = "/api/v1/users/profile/settings/notifications/email";
        assert_eq!(redact_pii(input), input);
    }

    #[test]
    fn test_high_entropy_does_not_double_redact_named_token() {
        // A named secret is redacted once; the catch-all must skip the PII_ token.
        let input = "key=AIzaSyA1234567890abcdefghijklmnopqrstuv";
        let output = redact_pii(input);
        assert!(output.contains("PII_GOOGLEKEY_"));
        assert!(!output.contains("PII_SECRET_"));
    }

    #[test]
    fn test_anomaly_basic_path() {
        let f = compute_anomaly_features("/api/v1/users/list", None);
        assert_eq!(f.path_depth, 4);
        assert_eq!(f.query_param_count, 0);
        assert!(!f.has_encoded_chars);
        assert_eq!(f.request_size_bucket, 0);
        assert!(!f.has_sqli_pattern);
        assert!(!f.has_xss_pattern);
        assert!(!f.has_path_traversal);
        assert!(f.shannon_entropy > 0.0);
    }

    #[test]
    fn test_anomaly_query_param_count_and_encoding() {
        let f = compute_anomaly_features("/search?q=hello%20world&page=2&sort=asc", None);
        assert_eq!(f.query_param_count, 3);
        assert!(f.has_encoded_chars);
    }

    #[test]
    fn test_anomaly_sqli_detection() {
        let f = compute_anomaly_features("/items?id=1' OR '1'='1", None);
        assert!(f.has_sqli_pattern);
        // Encoded variant is decoded before matching.
        let f2 = compute_anomaly_features("/items?q=%27%20OR%201=1%20--%20", None);
        assert!(f2.has_sqli_pattern);
        let f3 =
            compute_anomaly_features("/items?q=UNION%20SELECT%20password%20FROM%20users", None);
        assert!(f3.has_sqli_pattern);
    }

    #[test]
    fn test_anomaly_xss_detection() {
        let f = compute_anomaly_features("/page?name=<script>alert(1)</script>", None);
        assert!(f.has_xss_pattern);
        let f2 = compute_anomaly_features("/p?x=%3Cimg%20src=x%20onerror=alert(1)%3E", None);
        assert!(f2.has_xss_pattern);
    }

    #[test]
    fn test_anomaly_path_traversal_detection() {
        let f = compute_anomaly_features("/files?name=../../etc/passwd", None);
        assert!(f.has_path_traversal);
        let f2 = compute_anomaly_features("/files?name=..%2f..%2fetc%2fpasswd", None);
        assert!(f2.has_path_traversal);
    }

    #[test]
    fn test_anomaly_benign_no_false_positives() {
        let f = compute_anomaly_features("/v1/products?category=books&inStock=true", None);
        assert!(!f.has_sqli_pattern);
        assert!(!f.has_xss_pattern);
        assert!(!f.has_path_traversal);
    }

    #[test]
    fn test_anomaly_size_bucket_from_body() {
        let body = "x".repeat(5000);
        let f = compute_anomaly_features("/upload", Some(&body));
        assert_eq!(f.request_size_bucket, 3); // 4096..=16383
    }

    #[test]
    fn test_shannon_entropy_bounds() {
        assert_eq!(super::shannon_entropy(""), 0.0);
        // A single repeated char has zero entropy.
        assert_eq!(super::shannon_entropy("aaaaaaaa"), 0.0);
        // Mixed content has positive entropy.
        assert!(super::shannon_entropy("a1B2c3D4") > 2.0);
    }

    #[test]
    fn test_credit_card_luhn_validation() {
        // Valid Visa card (passes Luhn)
        let input = "card: 4111111111111111";
        let output = redact_pii(input);
        assert!(output.contains("PII_CARD_"));
        // Invalid card number (fails Luhn) — should NOT be redacted
        let input = "num: 4111111111111112";
        let output = redact_pii(input);
        assert!(output.contains("4111111111111112"));
    }
}
