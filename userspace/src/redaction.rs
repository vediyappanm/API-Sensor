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
    /// A value whose *name* marks it secret (cookie, password, api key, ...), so it
    /// is tokenised regardless of what the value looks like.
    Secret,
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
        PiiType::Secret      => format!("PII_SECRET_{h}"),
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
        // The whole PEM block, not just the BEGIN line: the base64 body IS the key.
        // A body capped mid-key has no END marker, so run to the end of the text.
        (PiiType::PrivateKey,
         Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)").unwrap()),
        (PiiType::Phone,
         Regex::new(r"\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s][2-9]\d{2}[-.\s]\d{4}\b").unwrap()),
        // Indian PAN (ABCDE1234F format)
        (PiiType::IndianPan,
         Regex::new(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b").unwrap()),
        // Aadhaar: 12 digits (4-4-4, optional space/dash), first digit 2-9, and the last
        // digit is a Verhoeff check digit. Without the checksum every 12-digit id,
        // order number or timestamp was destroyed as "PII".
        (PiiType::Aadhaar,
         Regex::new(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b").unwrap()),
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

/// Verhoeff checksum (the check Aadhaar numbers use). `digits` includes the check digit.
fn verhoeff_valid(digits: &str) -> bool {
    const D: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    const P: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    let mut c = 0u8;
    for (i, d) in digits
        .chars()
        .filter_map(|ch| ch.to_digit(10))
        .rev()
        .enumerate()
    {
        c = D[c as usize][P[i % 8][d as usize] as usize];
    }
    c == 0
}

pub fn redact_pii(text: &str) -> String {
    let patterns = PII_PATTERNS.get_or_init(init_pii_patterns);
    let mut result = text.to_string();
    for (pii_type, pattern) in patterns {
        // Collect all matches first (owned), so the borrow of `result` ends before
        // we mutate it below.
        let ranges: Vec<(usize, usize, String)> = pattern
            .find_iter(&result)
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
                match pii_type {
                    PiiType::CreditCard => luhn_check(s),
                    PiiType::Aadhaar => verhoeff_valid(s),
                    _ => true,
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
// Name-aware redaction
//
// `redact_pii` only sees a bare string, so it can only catch secrets that LOOK like
// something (a JWT, a card number). A session cookie, API key or password has no
// recognisable shape; the only signal is the NAME it travels under. The functions
// below use that name (header name, JSON key, form field, XML element, URL param)
// and tokenise the value with the same keyed HMAC, so equal secrets still correlate
// across requests but the secret itself never leaves the process.
// ---------------------------------------------------------------------------

/// Names that always denote a secret. Matched after lowercasing and dropping
/// `-`, `_`, `.`, `[`, `]` so `X-Api-Key`, `api_key` and `apiKey` are one name.
const SECRET_NAME_PARTS: &[&str] = &[
    "authorization", "cookie", "password", "passwd", "passphrase", "secret", "token",
    "apikey", "accesskey", "privatekey", "credential", "session", "signature",
    "csrf", "xsrf",
];
/// Short names where substring matching would hit unrelated words ("pin" in "shipping"),
/// so they must match the whole normalised name.
const SECRET_NAME_EXACT: &[&str] = &["pwd", "pin", "otp", "cvv", "cvc", "sid", "ssn", "key", "auth"];
/// Names that carry a secret even when the value is a number/boolean (a PIN is digits).
const STRONG_NAME_PARTS: &[&str] = &["password", "passwd", "passphrase", "secret", "privatekey", "credential"];
const STRONG_NAME_EXACT: &[&str] = &["pwd", "pin", "otp", "cvv", "cvc", "ssn"];

fn normalise_name(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.' | '[' | ']'))
        .flat_map(|c| c.to_lowercase())
        .collect()
}

pub fn is_sensitive_name(name: &str) -> bool {
    let n = normalise_name(name);
    !n.is_empty()
        && (SECRET_NAME_EXACT.contains(&n.as_str()) || SECRET_NAME_PARTS.iter().any(|p| n.contains(p)))
}

fn is_strong_name(name: &str) -> bool {
    let n = normalise_name(name);
    STRONG_NAME_EXACT.contains(&n.as_str()) || STRONG_NAME_PARTS.iter().any(|p| n.contains(p))
}

fn secret_token(value: &str) -> String {
    pii_token(&PiiType::Secret, value)
}

/// 16 hex chars of the keyed hash of `value`: a stable, non-reversible identifier for
/// a session/credential that can be correlated across events without exposing it.
pub fn fingerprint(value: &str) -> String {
    let t = secret_token(value);
    t.trim_start_matches("PII_SECRET_").chars().take(16).collect()
}

struct SecretScrubbers {
    pem: Regex,
    url_userinfo: Regex,
    json_kv: Regex,
    form_kv: Regex,
    xml_el: Regex,
}

static SCRUBBERS: OnceLock<SecretScrubbers> = OnceLock::new();

fn scrubbers() -> &'static SecretScrubbers {
    SCRUBBERS.get_or_init(|| SecretScrubbers {
        pem: Regex::new(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)").unwrap(),
        // scheme://user:PASSWORD@host
        url_userinfo: Regex::new(r"(://[^/\s:@?#]{1,100}:)([^/\s@?#]{1,200})(@)").unwrap(),
        // "key": value  -- value is a quoted string (possibly cut off at the end of a
        // capped body) or a bare scalar. Works on invalid/truncated JSON, which a
        // parse-then-walk approach would not.
        json_kv: Regex::new(r#""((?:[^"\\]|\\.){1,100})"\s*:\s*("(?:[^"\\]|\\.)*"?|[^\s,{}\[\]"][^\s,}\]]*)"#).unwrap(),
        // key=value in a query string / form body
        form_kv: Regex::new(r#"(^|[?&;\s])([A-Za-z0-9_.\-\[\]%]{1,100})=([^&\s;"'<>]*)"#).unwrap(),
        xml_el: Regex::new(r"<([A-Za-z_][\w.\-]{0,60})>([^<]{1,2000})</([A-Za-z_][\w.\-]{0,60})>").unwrap(),
    })
}

/// Replace secret-bearing key/value pairs, PEM blocks and URL credentials. Does not
/// run the value-shape patterns; callers that want both use `redact_text`.
fn scrub_secrets(text: &str) -> String {
    let s = scrubbers();
    let out = s.pem.replace_all(text, "PII_PRIVATE_KEY_REDACTED");
    let out = s.url_userinfo.replace_all(&out, |c: &regex::Captures| {
        format!("{}{}{}", &c[1], secret_token(&c[2]), &c[3])
    });
    let out = s.json_kv.replace_all(&out, |c: &regex::Captures| {
        let (key, val) = (&c[1], &c[2]);
        if !is_sensitive_name(key) || val.starts_with('{') || val.starts_with('[') || val.starts_with("PII_") {
            return c[0].to_string();
        }
        let quoted = val.starts_with('"');
        // Numbers/booleans/null under a merely-"token-ish" name (e.g. `tokens_used: 42`)
        // are metrics, not secrets. Strong names (password, pin, otp...) are always redacted.
        if !quoted && !is_strong_name(key) {
            return c[0].to_string();
        }
        let inner = val.trim_matches('"');
        if inner.is_empty() || inner.starts_with("PII_") {
            return c[0].to_string();
        }
        let key_end = c[0].len() - val.len();
        format!("{}\"{}\"", &c[0][..key_end], secret_token(inner))
    });
    let out = s.form_kv.replace_all(&out, |c: &regex::Captures| {
        if is_sensitive_name(&c[2]) && !c[3].is_empty() && !c[3].starts_with("PII_") {
            format!("{}{}={}", &c[1], &c[2], secret_token(&c[3]))
        } else {
            c[0].to_string()
        }
    });
    let out = s.xml_el.replace_all(&out, |c: &regex::Captures| {
        if c[1] == c[3] && is_sensitive_name(&c[1]) && !c[2].trim().is_empty() && !c[2].starts_with("PII_") {
            format!("<{0}>{1}</{0}>", &c[1], secret_token(c[2].trim()))
        } else {
            c[0].to_string()
        }
    });
    out.into_owned()
}

/// Full redaction for free text (bodies, URLs, non-sensitive header values):
/// name-keyed secrets first, then value-shape PII.
pub fn redact_text(text: &str) -> String {
    redact_pii(&scrub_secrets(text))
}

/// Redact a request target (`/path?query`): `?token=...&api_key=...`, `user:pass@`, PII.
pub fn redact_url(target: &str) -> String {
    redact_text(target)
}

fn cookie_pairs(value: &str, redact_all_values: bool) -> String {
    value
        .split(';')
        .map(|pair| match pair.split_once('=') {
            Some((name, val)) if !val.trim().is_empty() && (redact_all_values || is_sensitive_name(name)) => {
                format!("{}={}", name, secret_token(val.trim()))
            }
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join(";")
}

/// Redact one header value using the header's name.
///  * `Authorization`/`Proxy-Authorization`: keep the scheme word, tokenise the credential.
///  * `Cookie`: keep cookie names, tokenise every value.
///  * `Set-Cookie`: tokenise the cookie's value, keep attributes (Path, Expires, HttpOnly...).
///  * any other secret-named header (`X-Api-Key`, `X-Auth-Token`, ...): tokenise the value.
///  * everything else: key/value scrubbing + value-shape PII (catches `Referer: ...?token=x`).
/// Multi-valued headers joined with newlines are handled line by line.
pub fn redact_header_value(name: &str, value: &str) -> String {
    let lname = name.to_ascii_lowercase();
    value
        .split('\n')
        .map(|line| redact_header_line(&lname, line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_header_line(lname: &str, value: &str) -> String {
    if value.trim().is_empty() || value.starts_with("PII_") {
        return value.to_string();
    }
    match lname {
        "authorization" | "proxy-authorization" => match value.trim().split_once(char::is_whitespace) {
            Some((scheme, cred)) if !cred.trim().is_empty() => format!("{} {}", scheme, secret_token(cred.trim())),
            _ => secret_token(value.trim()),
        },
        "cookie" => cookie_pairs(value, true),
        "set-cookie" => match value.split_once(';') {
            Some((first, attrs)) => format!("{};{}", cookie_pairs(first, true), attrs),
            None => cookie_pairs(value, true),
        },
        _ if is_sensitive_name(lname) => secret_token(value.trim()),
        _ => redact_text(value),
    }
}

/// Redact a captured body (JSON, form, XML, text — truncated or not).
pub fn redact_body(text: &str) -> String {
    redact_text(text)
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
        // A real Aadhaar needs first digit 2-9 and a Verhoeff check digit. The old fixture
        // "1234 5678 9012" only matched because ANY 12 digits used to match.
        let valid = (0..10)
            .map(|d| format!("23456789012{d}"))
            .find(|c| super::verhoeff_valid(c))
            .unwrap();
        let spaced = format!("{} {} {}", &valid[..4], &valid[4..8], &valid[8..]);
        let output = redact_pii(&format!("Aadhaar: {spaced}"));
        assert!(!output.contains(&spaced));
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

#[cfg(test)]
mod name_aware_tests {
    use super::*;

    fn key() {
        init_pii_hash_key_for_tests(&[0x42u8; 32]);
    }

    /// Fake secrets only; none matches a real provider's format.
    const SECRETS: &[&str] = &[
        "hunter2-correct-horse", "s3ssion-value-abcdef0123456789", "zZ9-api-key-0001",
        "dXNlcjpwYXNzd29yZA==", "my$ecretPassw0rd", "refresh-opaque-1a2b3c",
    ];

    fn assert_clean(out: &str) {
        for s in SECRETS {
            assert!(!out.contains(s), "secret {s:?} survived in: {out}");
        }
    }

    #[test]
    fn authorization_basic_keeps_scheme_drops_credential() {
        key();
        let out = redact_header_value("Authorization", "Basic dXNlcjpwYXNzd29yZA==");
        assert!(out.starts_with("Basic PII_SECRET_"), "{out}");
        assert_clean(&out);
        assert!(redact_header_value("authorization", "Bearer opaque-token-xyz").starts_with("Bearer PII_SECRET_"));
    }

    #[test]
    fn cookie_keeps_names_hides_every_value() {
        key();
        let out = redact_header_value("cookie", "theme=dark; sessionid=s3ssion-value-abcdef0123456789; lang=en");
        assert_clean(&out);
        assert!(out.contains("sessionid=PII_SECRET_") && out.contains("theme=PII_SECRET_"), "{out}");
    }

    #[test]
    fn set_cookie_hides_value_keeps_attributes() {
        key();
        let out = redact_header_value("Set-Cookie", "sid=s3ssion-value-abcdef0123456789; Path=/; HttpOnly; Secure; SameSite=Lax");
        assert_clean(&out);
        assert!(out.contains("Path=/; HttpOnly; Secure; SameSite=Lax"), "attributes lost: {out}");
    }

    #[test]
    fn multiple_set_cookie_lines_are_each_redacted() {
        key();
        let out = redact_header_value("set-cookie", "a=hunter2-correct-horse; Path=/\nb=my$ecretPassw0rd; Path=/");
        assert_clean(&out);
    }

    #[test]
    fn secret_named_headers_are_tokenised_whatever_the_value_looks_like() {
        key();
        for name in ["X-Api-Key", "x-auth-token", "X-CSRF-Token", "x-amz-security-token", "Private-Token", "X-Session-Id"] {
            let out = redact_header_value(name, "zZ9-api-key-0001");
            assert_clean(&out);
            assert!(out.starts_with("PII_SECRET_"), "{name}: {out}");
        }
    }

    #[test]
    fn ordinary_headers_survive_and_referer_tokens_do_not() {
        key();
        assert_eq!(redact_header_value("content-type", "application/json"), "application/json");
        assert_eq!(redact_header_value("user-agent", "curl/8.5.0"), "curl/8.5.0");
        assert_eq!(redact_header_value(":authority", "api.example.com"), "api.example.com");
        let out = redact_header_value("referer", "https://app.example.com/cb?access_token=refresh-opaque-1a2b3c&x=1");
        assert_clean(&out);
        assert!(out.contains("x=1"));
    }

    #[test]
    fn json_secrets_redacted_at_any_depth_and_siblings_kept() {
        key();
        let body = r#"{"user":"alice","password":"hunter2-correct-horse","profile":{"api_key":"zZ9-api-key-0001","age":30},
            "items":[{"id":1,"refresh_token":"refresh-opaque-1a2b3c"}],"tokens_used":42,"pin":1234}"#;
        let out = redact_body(body);
        assert_clean(&out);
        assert!(out.contains("\"user\":\"alice\"") && out.contains("\"age\":30") && out.contains("\"id\":1"), "{out}");
        assert!(out.contains("\"tokens_used\":42"), "usage metric must not be destroyed: {out}");
        assert!(!out.contains("1234"), "numeric PIN must be redacted: {out}");
    }

    #[test]
    fn truncated_json_body_still_redacts_the_cut_off_secret() {
        key();
        // Bodies are capped at 8 KiB, so the secret's closing quote can be missing.
        let out = redact_body(r#"{"a":1,"password":"hunter2-correct-horse"#);
        assert_clean(&out);
        let out = redact_body(r#"{"a":1,"password":"hunter2-correct-horse","b":"#);
        assert_clean(&out);
    }

    #[test]
    fn json_with_escaped_quotes_in_value_is_fully_redacted() {
        key();
        let out = redact_body(r#"{"password":"hunter2-correct-horse\"tail","ok":true}"#);
        assert_clean(&out);
        assert!(!out.contains("tail"), "{out}");
        assert!(out.contains("\"ok\":true"));
    }

    #[test]
    fn form_and_query_secrets_are_redacted() {
        key();
        assert_clean(&redact_body("username=alice&password=hunter2-correct-horse&remember=1"));
        let out = redact_url("/cb?code=1&access_token=refresh-opaque-1a2b3c&page=2");
        assert_clean(&out);
        assert!(out.contains("page=2") && out.contains("code=1"), "{out}");
    }

    #[test]
    fn xml_secrets_are_redacted() {
        key();
        let out = redact_body("<login><user>alice</user><password>hunter2-correct-horse</password></login>");
        assert_clean(&out);
        assert!(out.contains("<user>alice</user>"));
    }

    #[test]
    fn url_userinfo_password_is_redacted() {
        key();
        let out = redact_body("callback=https://svc:my$ecretPassw0rd@internal.example.com/hook");
        assert_clean(&out);
        assert!(out.contains("internal.example.com"));
    }

    #[test]
    fn private_key_body_is_redacted_not_just_the_header_line() {
        key();
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\nZm9vYmFyYmF6\n-----END PRIVATE KEY-----";
        let out = redact_body(&format!("key: {pem} trailing"));
        assert!(!out.contains("MIIEvQ") && !out.contains("Zm9vYmFy"), "{out}");
        assert!(out.contains("PII_PRIVATE_KEY_REDACTED") && out.contains("trailing"));
        // capped mid-key: no END marker
        let cut = redact_body("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA");
        assert!(!cut.contains("MIIEow"), "{cut}");
    }

    #[test]
    fn already_redacted_values_are_not_double_wrapped() {
        key();
        let once = redact_body(r#"{"password":"hunter2-correct-horse"}"#);
        assert_eq!(redact_body(&once), once);
    }

    #[test]
    fn tokens_are_deterministic_so_a_session_can_still_be_correlated() {
        key();
        let a = redact_header_value("cookie", "sid=same-value");
        let b = redact_header_value("cookie", "sid=same-value");
        let c = redact_header_value("cookie", "sid=other-value");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(fingerprint("x").len(), 16);
    }

    /// Find a Verhoeff check digit so the test does not depend on a real Aadhaar number.
    fn with_verhoeff(prefix: &str) -> String {
        (0..10).map(|d| format!("{prefix}{d}")).find(|c| verhoeff_valid(c)).unwrap()
    }

    #[test]
    fn aadhaar_requires_a_valid_checksum_so_plain_ids_are_kept() {
        key();
        let valid = with_verhoeff("23456789012");
        let spaced = format!("{} {} {}", &valid[..4], &valid[4..8], &valid[8..]);
        assert!(redact_pii(&format!("aadhaar {spaced}")).contains("PII_AADHAAR_"));
        // A 12-digit order id with a bad checksum is NOT PII.
        let not_valid = (0..10).map(|d| format!("23456789012{d}")).find(|c| !verhoeff_valid(c)).unwrap();
        assert!(redact_pii(&format!("order {not_valid}")).contains(&not_valid));
        // First digit 0/1 cannot be Aadhaar.
        assert!(redact_pii("id 123456789012").contains("123456789012"));
    }

    #[test]
    fn redaction_is_linear_time_on_hostile_input() {
        key();
        let nasty = format!("{}\"password\":\"{}", "\"a\":".repeat(20_000), "x\\".repeat(20_000));
        let start = std::time::Instant::now();
        let _ = redact_body(&nasty);
        assert!(start.elapsed().as_secs() < 5, "redaction too slow: {:?}", start.elapsed());
    }
}
