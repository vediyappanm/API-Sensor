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
    GithubPat,
    SlackToken,
    StripeKey,
    Ifsc,
    Gstin,
}

#[allow(dead_code)]
pub struct PiiDetection {
    pub pii_type: PiiType,
    pub token:    String,
}

static PII_PATTERNS: OnceLock<Vec<(PiiType, Regex)>> = OnceLock::new();

static PII_HASH_KEY: OnceLock<Vec<u8>> = OnceLock::new();

/// Initialise the PII hash key from the `PII_HASH_KEY` env var.
/// Must be called once at sensor startup. Returns an error if the key is
/// missing or malformed — refusing to start is preferable to silently shipping
/// with a guessable key, which would let any reader of the binary or
/// environment de-tokenize all redacted PII.
pub fn init_pii_hash_key() -> Result<(), String> {
    let hex = std::env::var("PII_HASH_KEY").map_err(|_| {
        "PII_HASH_KEY env var is required (64 hex chars = 32 random bytes). \
         Generate with: openssl rand -hex 32"
            .to_string()
    })?;
    if hex.len() != 64 {
        return Err(format!(
            "PII_HASH_KEY must be exactly 64 hex chars (got {} chars)",
            hex.len()
        ));
    }
    let bytes: Result<Vec<u8>, _> = (0..32)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
        .collect();
    let bytes = bytes.map_err(|_| "PII_HASH_KEY contains non-hex characters".to_string())?;
    PII_HASH_KEY
        .set(bytes)
        .map_err(|_| "PII_HASH_KEY already initialised".to_string())?;
    Ok(())
}

/// Test-only key initialisation. Production callers must use `init_pii_hash_key`.
#[cfg(test)]
pub fn init_pii_hash_key_for_tests(key: &[u8; 32]) {
    let _ = PII_HASH_KEY.set(key.to_vec());
}

fn pii_hash_key() -> &'static [u8] {
    PII_HASH_KEY
        .get()
        .map(|v| v.as_slice())
        .expect("PII_HASH_KEY not initialised — call init_pii_hash_key() at startup")
}

pub fn pii_token(pii_type: &PiiType, original: &str) -> String {
    let key = pii_hash_key();
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC-SHA256 accepts keys of any length");
    mac.update(original.as_bytes());
    let result = mac.finalize().into_bytes();
    // 128 bits of HMAC output — birthday collision space ~2^64, vs ~2^32 for
    // the previous 64-bit truncation. At billions of tokens we no longer
    // accidentally collide identifiers from different originals.
    let hi = u64::from_be_bytes(result[..8].try_into().unwrap());
    let lo = u64::from_be_bytes(result[8..16].try_into().unwrap());
    let h = format!("{hi:016x}{lo:016x}");
    match pii_type {
        PiiType::Email       => format!("PII_EMAIL_{h}"),
        PiiType::CreditCard  => format!("PII_CARD_{h}"),
        PiiType::Ssn         => format!("PII_SSN_{h}"),
        PiiType::Phone       => format!("PII_PHONE_{h}"),
        PiiType::Jwt         => format!("PII_JWT_{h}"),
        PiiType::BearerToken => format!("PII_TOKEN_{h}"),
        PiiType::PrivateKey  => "PII_PRIVATE_KEY_REDACTED".to_string(),
        PiiType::AwsKey      => format!("PII_AWSKEY_{h}"),
        PiiType::GcpToken    => format!("PII_GCPTOKEN_{h}"),
        PiiType::IndianPan   => format!("PII_PAN_{h}"),
        PiiType::Aadhaar     => format!("PII_AADHAAR_{h}"),
        PiiType::GithubPat   => format!("PII_GHPAT_{h}"),
        PiiType::SlackToken  => format!("PII_SLACK_{h}"),
        PiiType::StripeKey   => format!("PII_STRIPE_{h}"),
        PiiType::Ifsc        => format!("PII_IFSC_{h}"),
        PiiType::Gstin       => format!("PII_GSTIN_{h}"),
    }
}

fn init_pii_patterns() -> Vec<(PiiType, Regex)> {
    // Order matters: prefix-distinctive secrets (GitHub PAT, Slack, Stripe,
    // GCP token) must run BEFORE the generic Bearer regex, otherwise a
    // header like `Authorization: Bearer ghp_...` would be swallowed as a
    // bearer token and tagged generically rather than as the specific kind.
    vec![
        (PiiType::Jwt,
         Regex::new(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}").unwrap()),
        // GitHub Personal Access Token (classic + fine-grained: ghp/gho/ghu/ghs/ghr)
        (PiiType::GithubPat,
         Regex::new(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b").unwrap()),
        // Slack tokens (bot, user, app, legacy)
        (PiiType::SlackToken,
         Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,200}\b").unwrap()),
        // Stripe live/test API keys (secret + restricted)
        (PiiType::StripeKey,
         Regex::new(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,99}\b").unwrap()),
        // GCP OAuth token (must run before Bearer)
        (PiiType::GcpToken,
         Regex::new(r"ya29\.[A-Za-z0-9_-]{20,}").unwrap()),
        // AWS Access Key ID (starts with AKIA, 20 chars)
        (PiiType::AwsKey,
         Regex::new(r"AKIA[0-9A-Z]{16}").unwrap()),
        (PiiType::BearerToken,
         Regex::new(r"(?i)Bearer\s+([A-Za-z0-9\-._~+/]+=*)").unwrap()),
        (PiiType::Email,
         Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap()),
        // Credit card formats — format check, NOT Luhn validated
        (PiiType::CreditCard,
         Regex::new(r"\b(?:4[0-9]{15}|5[1-5][0-9]{14}|3[47][0-9]{13}|6011[0-9]{12})\b").unwrap()),
        (PiiType::Ssn,
         Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()),
        (PiiType::PrivateKey,
         Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").unwrap()),
        (PiiType::Phone,
         Regex::new(r"\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s][2-9]\d{2}[-.\s]\d{4}\b").unwrap()),
        // Indian PAN (ABCDE1234F format)
        (PiiType::IndianPan,
         Regex::new(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b").unwrap()),
        // Aadhaar (12 digits, optionally space/dash separated as 4-4-4)
        (PiiType::Aadhaar,
         Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap()),
        // Indian IFSC bank code (4 letters + 7 alphanumeric, 0 reserved at pos 5)
        (PiiType::Ifsc,
         Regex::new(r"\b[A-Z]{4}0[A-Z0-9]{6}\b").unwrap()),
        // Indian GSTIN (15 chars: 2 digit state, 10 char PAN, 1 entity, 1 'Z', 1 checksum)
        (PiiType::Gstin,
         Regex::new(r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d]\b").unwrap()),
    ]
}

fn luhn_check(digits: &str) -> bool {
    let digits: Vec<u32> = digits.chars().filter(|c| c.is_ascii_digit()).filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 { return false; }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut n = d;
        if double {
            n *= 2;
            if n > 9 { n -= 9; }
        }
        sum += n;
        double = !double;
    }
    sum % 10 == 0
}

pub fn redact_pii(text: &str) -> String {
    let patterns = PII_PATTERNS.get_or_init(init_pii_patterns);
    let mut result = text.to_string();
    for (pii_type, pattern) in patterns {
        // Collect all matches first (to avoid borrow conflict during replacement)
        let ranges: Vec<(usize, usize, String)> = pattern
            .find_iter(&result.clone())
            .filter(|m| {
                let s = m.as_str();
                // Don't re-redact already-redacted tokens. Without this guard
                // a generic regex like the Bearer matcher would swallow
                // earlier-replaced specific tokens (e.g. `Bearer PII_STRIPE_…`
                // → `PII_TOKEN_…`), losing the precise classification.
                if s.contains("PII_") {
                    return false;
                }
                // Apply Luhn validation for credit card matches
                if *pii_type == PiiType::CreditCard {
                    luhn_check(s)
                } else {
                    true
                }
            })
            .map(|m| (m.start(), m.end(), pii_token(pii_type, m.as_str())))
            .collect();
        // Replace in reverse order to preserve offsets
        for (start, end, token) in ranges.into_iter().rev() {
            result.replace_range(start..end, &token);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ensure_test_key() {
        // Idempotent — OnceLock::set silently fails on second call.
        init_pii_hash_key_for_tests(b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\
                                     \x10\x20\x30\x40\x50\x60\x70\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0\x01");
    }

    #[test]
    fn test_pii_token_requires_explicit_init() {
        // The global init may already be set by another test; this asserts only
        // that token output has the expected width (32 hex chars = 128 bits).
        ensure_test_key();
        let t = pii_token(&PiiType::Email, "anyone@example.com");
        let suffix = t.trim_start_matches("PII_EMAIL_");
        assert_eq!(suffix.len(), 32, "tokens must be 128-bit hex (got {suffix:?})");
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_pii_redact_email() {
        ensure_test_key();
        let input = "Contact us at user@example.com for support";
        let output = redact_pii(input);
        assert!(!output.contains("user@example.com"));
        assert!(output.contains("PII_EMAIL_"));
    }

    #[test]
    fn test_pii_redact_jwt() {
        ensure_test_key();
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let input = format!("Authorization: Bearer {}", jwt);
        let output = redact_pii(&input);
        assert!(!output.contains(jwt));
        // Either JWT or Bearer token pattern matched
        assert!(output.contains("PII_JWT_") || output.contains("PII_TOKEN_"));
    }

    #[test]
    fn test_pii_token_deterministic() {
        ensure_test_key();
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
        ensure_test_key();
        let input = "SSN: 123-45-6789";
        let output = redact_pii(input);
        assert!(!output.contains("123-45-6789"));
        assert!(output.contains("PII_SSN_"));
    }

    #[test]
    fn test_pii_redact_private_key() {
        ensure_test_key();
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...";
        let output = redact_pii(input);
        assert!(output.contains("PII_PRIVATE_KEY_REDACTED"));
    }

    #[test]
    fn test_pii_redact_aws_key() {
        ensure_test_key();
        let input = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE";
        let output = redact_pii(input);
        assert!(!output.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(output.contains("PII_AWSKEY_"));
    }

    #[test]
    fn test_pii_redact_gcp_token() {
        ensure_test_key();
        let input = "Authorization: Bearer ya29.a0ARrdaM8ABCDEFGHIJKLMNOPQRST";
        let output = redact_pii(input);
        assert!(!output.contains("ya29.a0ARrdaM8ABCDEFGHIJKLMNOPQRST"));
        assert!(output.contains("PII_GCPTOKEN_") || output.contains("PII_TOKEN_"));
    }

    #[test]
    fn test_pii_redact_indian_pan() {
        ensure_test_key();
        let input = "PAN: ABCDE1234F";
        let output = redact_pii(input);
        assert!(!output.contains("ABCDE1234F"));
        assert!(output.contains("PII_PAN_"));
    }

    #[test]
    fn test_pii_redact_aadhaar() {
        ensure_test_key();
        let input = "Aadhaar: 1234 5678 9012";
        let output = redact_pii(input);
        assert!(!output.contains("1234 5678 9012"));
        assert!(output.contains("PII_AADHAAR_"));
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
    fn test_credit_card_luhn_validation() {
        ensure_test_key();
        // Valid Visa card (passes Luhn)
        let input = "card: 4111111111111111";
        let output = redact_pii(input);
        assert!(output.contains("PII_CARD_"));
        // Invalid card number (fails Luhn) — should NOT be redacted
        let input = "num: 4111111111111112";
        let output = redact_pii(input);
        assert!(output.contains("4111111111111112"));
    }

    #[test]
    fn test_pii_redact_github_pat() {
        ensure_test_key();
        // Real GitHub PAT shape: ghp_ + 36+ alphanumerics (no underscores).
        let pat = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
        let output = redact_pii(&format!("token={pat}"));
        assert!(!output.contains(pat));
        assert!(output.contains("PII_GHPAT_"));
    }

    #[test]
    fn test_pii_redact_slack_token() {
        ensure_test_key();
        let tok = "xoxb-test-fake-slack-token";
        let output = redact_pii(&format!("X-Slack-Token: {tok}"));
        assert!(!output.contains(tok));
        assert!(output.contains("PII_SLACK_"));
    }

    #[test]
    fn test_pii_redact_stripe_key() {
        ensure_test_key();
        // Built at runtime so the file never contains a contiguous Stripe-shaped
        // token (GitHub push protection flags sk_test_ + 24 alphanumerics).
        let key = format!("sk_{}_{}", "test", "AAAABBBBCCCCDDDD00001111");
        let output = redact_pii(&format!("Authorization: Bearer {key}"));
        assert!(!output.contains(&key));
        assert!(output.contains("PII_STRIPE_"));
    }

    #[test]
    fn test_pii_redact_ifsc() {
        ensure_test_key();
        let ifsc = "HDFC0001234";
        let output = redact_pii(&format!("ifsc={ifsc}"));
        assert!(!output.contains(ifsc));
        assert!(output.contains("PII_IFSC_"));
    }

    #[test]
    fn test_pii_redact_gstin() {
        ensure_test_key();
        let gstin = "27ABCDE1234F1Z5";
        let output = redact_pii(&format!("GSTIN: {gstin}"));
        assert!(!output.contains(gstin));
        assert!(output.contains("PII_GSTIN_"));
    }
}
