use hmac::{Hmac, Mac};
use rand::RngCore;
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
}

#[allow(dead_code)]
pub struct PiiDetection {
    pub pii_type: PiiType,
    pub token: String,
}

static PII_PATTERNS: OnceLock<Vec<(PiiType, Regex)>> = OnceLock::new();

static PII_HASH_KEY: OnceLock<Vec<u8>> = OnceLock::new();

/// Initialize PII HMAC key. In production mode (SENSOR_ENV=production), PII_HASH_KEY
/// is mandatory — the sensor will panic at startup if it's missing or malformed.
/// In non-production mode, a random key is generated as fallback.
fn pii_hash_key() -> &'static [u8] {
    PII_HASH_KEY.get_or_init(|| {
        let is_production = std::env::var("SENSOR_ENV")
            .map(|v| v.eq_ignore_ascii_case("production"))
            .unwrap_or(false);

        if let Ok(hex) = std::env::var("PII_HASH_KEY") {
            if hex.len() == 64 {
                let bytes: Option<Vec<u8>> = (0..32)
                    .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok())
                    .collect();
                if let Some(key) = bytes {
                    return key;
                }
            }
            if is_production {
                panic!("FATAL: PII_HASH_KEY must be 64 hex chars (32 bytes). Cannot start in production mode with invalid key.");
            }
            eprintln!("WARNING: PII_HASH_KEY must be 64 hex chars (32 bytes). Generating random key.");
        } else if is_production {
            panic!(
                "FATAL: PII_HASH_KEY env var is required when SENSOR_ENV=production. \
                 Generate with: openssl rand -hex 32"
            );
        } else {
            eprintln!("WARNING: PII_HASH_KEY not set. Generating random HMAC key — PII tokens will differ across restarts. Set PII_HASH_KEY env var (64 hex chars) for stable tokens.");
        }
        let mut key = vec![0u8; 32];
        rand::rng().fill_bytes(&mut key);
        key
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
        // Indian PAN (ABCDE1234F format)
        (
            PiiType::IndianPan,
            Regex::new(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b").unwrap(),
        ),
        // Aadhaar (12 digits, optionally space/dash separated as 4-4-4)
        (
            PiiType::Aadhaar,
            Regex::new(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap(),
        ),
    ]
}

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

pub fn redact_pii(text: &str) -> String {
    let patterns = PII_PATTERNS.get_or_init(init_pii_patterns);

    // Collect ALL matches from ALL patterns in one pass over the result string,
    // then apply replacements in reverse order. This avoids cloning per-pattern.
    let mut all_ranges: Vec<(usize, usize, String)> = Vec::new();
    for (pii_type, pattern) in patterns {
        for m in pattern.find_iter(text) {
            if *pii_type == PiiType::CreditCard && !luhn_check(m.as_str()) {
                continue;
            }
            all_ranges.push((m.start(), m.end(), pii_token(pii_type, m.as_str())));
        }
    }

    if all_ranges.is_empty() {
        return text.to_string();
    }

    // Sort by start position descending so replacements don't shift earlier offsets.
    // For overlapping matches, keep the one that starts earliest (last after reverse sort).
    all_ranges.sort_by(|a, b| b.0.cmp(&a.0));
    // Remove overlapping ranges (after reverse sort, skip if a range overlaps a later one)
    all_ranges.dedup_by(|later, earlier| later.0 < earlier.1);

    let mut result = text.to_string();
    for (start, end, token) in all_ranges {
        result.replace_range(start..end, &token);
    }
    result
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
        let input = "PAN: ABCDE1234F";
        let output = redact_pii(input);
        assert!(!output.contains("ABCDE1234F"));
        assert!(output.contains("PII_PAN_"));
    }

    #[test]
    fn test_pii_redact_aadhaar() {
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
