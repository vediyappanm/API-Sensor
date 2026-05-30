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

pub fn redact_pii(text: &str) -> String {
    let patterns = PII_PATTERNS.get_or_init(init_pii_patterns);
    let mut result = text.to_string();
    for (pii_type, pattern) in patterns {
        // Collect all matches first (to avoid borrow conflict during replacement)
        let ranges: Vec<(usize, usize, String)> = pattern
            .find_iter(&result.clone())
            .filter(|m| {
                // Apply Luhn validation for credit card matches
                if *pii_type == PiiType::CreditCard {
                    luhn_check(m.as_str())
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
