use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct IdentityInfo {
    pub user_id: String,
    pub user_role: String,
    pub session_id: String,
    pub auth_session_id: String,
}

/// Extract identity from HTTP request headers.
/// Tries (in order): JWT Bearer token, x-user-id header, cookie session.
pub fn extract_identity(headers: &HashMap<String, String>) -> IdentityInfo {
    let mut info = IdentityInfo {
        user_id: "unknown".to_string(),
        user_role: "unknown".to_string(),
        session_id: "sid-0".to_string(),
        auth_session_id: "0".to_string(),
    };

    // JWT from Authorization: Bearer <token>
    if let Some(auth) = headers.get("authorization") {
        let token = auth
            .strip_prefix("Bearer ")
            .or_else(|| auth.strip_prefix("bearer "))
            .or_else(|| auth.strip_prefix("Token "));
        if let Some(token) = token {
            if let Some(claims) = decode_jwt_payload(token.trim()) {
                if let Some(uid) = claims.get("sub")
                    .or_else(|| claims.get("user_id"))
                    .or_else(|| claims.get("uid"))
                    .or_else(|| claims.get("userId"))
                    .or_else(|| claims.get("email"))
                {
                    if let Some(s) = uid.as_str() {
                        if !s.is_empty() { info.user_id = s.to_string(); }
                    }
                }
                if let Some(role) = claims.get("role")
                    .or_else(|| claims.get("roles"))
                    .or_else(|| claims.get("scope"))
                    .or_else(|| claims.get("groups"))
                {
                    info.user_role = json_value_to_role_string(role);
                }
                if let Some(jti) = claims.get("jti") {
                    if let Some(s) = jti.as_str() {
                        if !s.is_empty() { info.auth_session_id = s.to_string(); }
                    }
                }
            }
        }
    }

    // Fallback: x-user-id / x-user-role headers
    if info.user_id == "unknown" {
        for key in &["x-user-id", "x-userid", "x-uid", "user-id"] {
            if let Some(v) = headers.get(*key) {
                if !v.is_empty() { info.user_id = v.clone(); break; }
            }
        }
    }
    if info.user_role == "unknown" {
        for key in &["x-user-role", "x-role", "x-roles"] {
            if let Some(v) = headers.get(*key) {
                if !v.is_empty() { info.user_role = v.clone(); break; }
            }
        }
    }

    // Session from cookie
    if let Some(cookie) = headers.get("cookie") {
        if let Some(sid) = extract_session_from_cookie(cookie) {
            info.session_id = sid;
        }
    }

    info
}

// ---------------------------------------------------------------------------
// JWT payload decoder (no signature verification — read-only sensor)
// ---------------------------------------------------------------------------

fn decode_jwt_payload(token: &str) -> Option<serde_json::Map<String, serde_json::Value>> {
    let mut parts = token.splitn(3, '.');
    let _header = parts.next()?;
    let payload_b64 = parts.next()?;
    // Skip trailing whitespace or null bytes that BPF may leave
    let payload_b64 = payload_b64.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '=');
    let decoded = base64url_decode(payload_b64)?;
    let val: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    val.as_object().cloned()
}

/// Minimal base64url decoder (RFC 4648 §5). No external crate needed.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    // Translate url-safe alphabet → standard, then add padding
    let mut s: Vec<u8> = input
        .bytes()
        .map(|b| match b { b'-' => b'+', b'_' => b'/', c => c })
        .collect();
    match s.len() % 4 {
        2 => { s.push(b'='); s.push(b'='); }
        3 => { s.push(b'='); }
        _ => {}
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < s.len() {
        let a = b64val(s[i])?;
        let b = b64val(s[i + 1])?;
        let c = b64val(s[i + 2])?;
        let d = b64val(s[i + 3])?;
        out.push((a << 2) | (b >> 4));
        if s[i + 2] != b'=' { out.push((b << 4) | (c >> 2)); }
        if s[i + 3] != b'=' { out.push((c << 6) | d); }
        i += 4;
    }
    Some(out)
}

fn b64val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+'        => Some(62),
        b'/'        => Some(63),
        b'='        => Some(0),
        _           => None,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn json_value_to_role_string(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|x| x.as_str())
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    }
}

fn extract_session_from_cookie(cookie: &str) -> Option<String> {
    const SESSION_KEYS: &[&str] = &[
        "sessionid", "session", "jsessionid", "phpsessid", "sid",
        "auth_session", "asid", "connect.sid",
    ];
    for pair in cookie.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            if SESSION_KEYS.contains(&k.trim().to_lowercase().as_str()) {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(format!("sid-{}", &v[..v.len().min(32)]));
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_decode() {
        // Header: {"alg":"HS256","typ":"JWT"}
        // Payload: {"sub":"user123","role":"admin","jti":"tok-abc","iat":1700000000}
        // (signature is ignored)
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                     eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwianRpIjoidG9rLWFiYyIsImlhdCI6MTcwMDAwMDAwMH0.\
                     SIG";
        let claims = decode_jwt_payload(token).unwrap();
        assert_eq!(claims["sub"].as_str().unwrap(), "user123");
        assert_eq!(claims["role"].as_str().unwrap(), "admin");
        assert_eq!(claims["jti"].as_str().unwrap(), "tok-abc");
    }

    #[test]
    fn test_extract_identity_bearer() {
        let mut hdrs = HashMap::new();
        hdrs.insert(
            "authorization".to_string(),
            "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwianRpIjoidG9rLWFiYyIsImlhdCI6MTcwMDAwMDAwMH0.\
             SIG".to_string(),
        );
        let id = extract_identity(&hdrs);
        assert_eq!(id.user_id, "user123");
        assert_eq!(id.user_role, "admin");
        assert_eq!(id.auth_session_id, "tok-abc");
    }

    #[test]
    fn test_extract_identity_header_fallback() {
        let mut hdrs = HashMap::new();
        hdrs.insert("x-user-id".to_string(), "u-99".to_string());
        hdrs.insert("x-user-role".to_string(), "viewer".to_string());
        let id = extract_identity(&hdrs);
        assert_eq!(id.user_id, "u-99");
        assert_eq!(id.user_role, "viewer");
    }

    #[test]
    fn test_extract_session_from_cookie() {
        let cookie = "theme=dark; sessionid=abc123def456; lang=en";
        let sid = extract_session_from_cookie(cookie).unwrap();
        assert_eq!(sid, "sid-abc123def456");
    }
}
