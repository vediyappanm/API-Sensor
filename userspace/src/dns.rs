use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// DNS reverse-resolution cache
// ---------------------------------------------------------------------------

const CACHE_TTL: Duration = Duration::from_secs(300);
const NEGATIVE_TTL: Duration = Duration::from_secs(60);
const MAX_ENTRIES: usize = 10_000;

struct CacheEntry {
    hostname: Option<String>,
    resolved_at: Instant,
    ttl: Duration,
}

pub struct DnsResolver {
    cache: Mutex<HashMap<IpAddr, CacheEntry>>,
    pending: Mutex<std::collections::HashSet<IpAddr>>,
    lookup_tx: mpsc::Sender<IpAddr>,
}

impl DnsResolver {
    pub fn new(lookup_tx: mpsc::Sender<IpAddr>) -> Self {
        Self {
            cache: Mutex::new(HashMap::new()),
            pending: Mutex::new(std::collections::HashSet::new()),
            lookup_tx,
        }
    }

    /// Non-blocking lookup: returns cached hostname if available, queues
    /// background resolution for unknown or expired IPs.
    pub fn lookup_and_queue(&self, ip_str: &str) -> Option<String> {
        let ip: IpAddr = ip_str.parse().ok()?;
        if ip.is_loopback() || is_link_local(&ip) {
            return None;
        }

        // Check cache
        {
            let cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = cache.get(&ip) {
                if entry.resolved_at.elapsed() < entry.ttl {
                    return entry.hostname.clone();
                }
            }
        }

        // Queue for background resolution (dedup via pending set)
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        // If the channel is full, skip — will retry on next event for this IP.
        if !pending.contains(&ip) && self.lookup_tx.try_send(ip).is_ok() {
            pending.insert(ip);
        }

        None
    }

    /// Insert a resolution result into the cache.
    pub fn insert(&self, ip: IpAddr, hostname: Option<String>) {
        let ttl = if hostname.is_some() {
            CACHE_TTL
        } else {
            NEGATIVE_TTL
        };

        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.len() >= MAX_ENTRIES {
            let now = Instant::now();
            cache.retain(|_, e| now.duration_since(e.resolved_at) < e.ttl);
        }
        cache.insert(
            ip,
            CacheEntry {
                hostname,
                resolved_at: Instant::now(),
                ttl,
            },
        );

        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.remove(&ip);
    }
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 169 && o[1] == 254
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

// ---------------------------------------------------------------------------
// Blocking reverse DNS via libc getnameinfo
// ---------------------------------------------------------------------------

/// Perform a blocking reverse-DNS (PTR) lookup.  Returns `None` when the
/// system resolver has no PTR record (or returns the bare IP string).
pub fn reverse_dns_lookup(ip: IpAddr) -> Option<String> {
    let mut host = [0u8; 256];

    let rc = match ip {
        IpAddr::V4(v4) => {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
            unsafe {
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    host.as_mut_ptr() as *mut libc::c_char,
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                )
            }
        }
        IpAddr::V6(v6) => {
            let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sa.sin6_addr.s6_addr = v6.octets();
            unsafe {
                libc::getnameinfo(
                    &sa as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    host.as_mut_ptr() as *mut libc::c_char,
                    host.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    0,
                )
            }
        }
    };

    if rc != 0 {
        return None;
    }

    let hostname = unsafe { std::ffi::CStr::from_ptr(host.as_ptr() as *const libc::c_char) };
    let name = hostname.to_str().ok()?.to_string();

    // getnameinfo returns the IP string when there is no PTR record
    if name == ip.to_string() {
        return None;
    }

    Some(name)
}

// ---------------------------------------------------------------------------
// Process name resolution
// ---------------------------------------------------------------------------

/// Extract process name from BPF-captured comm field, falling back to
/// /proc/<pid>/comm when the BPF field is empty.
pub fn read_process_name(pid: u32, bpf_comm: &[u8; 16]) -> Option<String> {
    let end = bpf_comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(bpf_comm.len());
    if end > 0 {
        let name = String::from_utf8_lossy(&bpf_comm[..end]).into_owned();
        if !name.is_empty() {
            return Some(name);
        }
    }
    // Fallback: read from procfs
    std::fs::read_to_string(format!("/proc/{}/comm", pid))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_process_name_from_comm() {
        let mut comm = [0u8; 16];
        comm[..5].copy_from_slice(b"nginx");
        assert_eq!(read_process_name(1, &comm), Some("nginx".to_string()));
    }

    #[test]
    fn test_read_process_name_empty_comm() {
        let comm = [0u8; 16];
        // Falls back to /proc/1/comm (init/systemd — may or may not exist in CI)
        let result = read_process_name(1, &comm);
        // Just verify it doesn't panic; result depends on runtime environment
        let _ = result;
    }

    #[test]
    fn test_is_link_local_v4() {
        assert!(is_link_local(&"169.254.1.1".parse().unwrap()));
        assert!(!is_link_local(&"10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_is_link_local_v6() {
        assert!(is_link_local(&"fe80::1".parse().unwrap()));
        assert!(!is_link_local(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_reverse_dns_loopback() {
        // Loopback should resolve to "localhost" on most systems
        let result = reverse_dns_lookup("127.0.0.1".parse().unwrap());
        // May or may not resolve depending on system config; just ensure no panic
        let _ = result;
    }

    #[test]
    fn test_dns_cache_insert_lookup() {
        let (tx, _rx) = mpsc::channel(16);
        let resolver = DnsResolver::new(tx);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        resolver.insert(ip, Some("my-service.local".to_string()));
        assert_eq!(
            resolver.lookup_and_queue("10.0.0.1"),
            Some("my-service.local".to_string())
        );
    }

    #[test]
    fn test_dns_cache_negative() {
        let (tx, _rx) = mpsc::channel(16);
        let resolver = DnsResolver::new(tx);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        resolver.insert(ip, None);
        // Negative cache entry returns None (no hostname)
        assert_eq!(resolver.lookup_and_queue("10.0.0.2"), None);
    }
}
