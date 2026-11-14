//! Multi-user authentication: PBKDF2 password hashes, HMAC-signed session
//! cookies, HTTP Basic fallback for API clients, per-IP login throttling.
//!
//! Password hash format (self-describing, versioned by algorithm name):
//!   pbkdf2-sha256$<iterations>$<salt_b64>$<hash_b64>
//!
//! Session token: `v1.<b64url payload>.<b64url hmac-sha256>` where payload is
//! `user|role|exp_unix|nonce`. Tokens are stateless — they survive across
//! requests but not restarts unless `server.session_secret` is configured
//! (otherwise a random per-boot key is used, invalidating sessions on
//! restart — a reasonable default).

use base64::Engine;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use serde::Deserialize;
use sha2::Sha256;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const ALGO: &str = "pbkdf2-sha256";
/// OWASP-recommended PBKDF2-HMAC-SHA256 iteration count.
pub const PBKDF2_ITERS: u32 = 600_000;
const SESSION_TTL_DEFAULT: u64 = 86_400; // 24h
/// Failed logins before the IP is temporarily locked out.
const MAX_FAILS: u32 = 5;
/// Lockout grows with each failure beyond MAX_FAILS, capped at 1h.
const LOCKOUT_BASE_SECS: u64 = 30;
const LOCKOUT_MAX_SECS: u64 = 3600;
/// Verified-Basic cache TTL — API clients (curl -u, scripts) would
/// otherwise pay a 600k-iteration PBKDF2 on every single request.
const BASIC_CACHE_MS: u64 = 60_000;
const BASIC_CACHE_MAX: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Viewer,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Viewer => "viewer",
        }
    }
    /// Viewers are read-only and cannot see admin endpoints.
    pub fn is_admin(&self) -> bool {
        matches!(self, Role::Admin)
    }
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct UserConfig {
    pub name: String,
    /// `pbkdf2-sha256$iters$salt_b64$hash_b64` — generate with
    /// `bgflowd hash-password`.
    pub password_hash: String,
    #[serde(default = "default_role")]
    pub role: Role,
}

fn default_role() -> Role {
    Role::Viewer
}

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub pass_hash: String,
    pub role: Role,
}

impl User {
    pub fn from_config(u: &UserConfig) -> Result<Self, String> {
        if u.name.is_empty()
            || !u
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(format!(
                "user '{}' has invalid name (allowed: [a-zA-Z0-9._-])",
                u.name
            ));
        }
        parse_hash(&u.password_hash)
            .ok_or_else(|| format!("user '{}': bad password_hash format", u.name))?;
        Ok(User {
            name: u.name.clone(),
            pass_hash: u.password_hash.clone(),
            role: u.role,
        })
    }
}

fn b64e(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn b64d(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .ok()
}

fn b64url_e(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn b64url_d(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok()
}

/// Parse `algo$iters$salt$hash`; returns (iters, salt, expected).
fn parse_hash(h: &str) -> Option<(u32, Vec<u8>, Vec<u8>)> {
    let mut parts = h.split('$');
    if parts.next()? != ALGO {
        return None;
    }
    let iters: u32 = parts.next()?.parse().ok()?;
    if iters < 10_000 || iters > 10_000_000 {
        return None;
    }
    let salt = b64d(parts.next()?)?;
    let hash = b64d(parts.next()?)?;
    if salt.is_empty() || hash.len() != 32 || parts.next().is_some() {
        return None;
    }
    Some((iters, salt, hash))
}

/// Hash a password for `[[users]]` config. ~0.3-0.6s per call.
pub fn hash_password(password: &str) -> String {
    hash_password_iters(password, PBKDF2_ITERS)
}

/// Iteration-count-parameterized variant (tests use the floor to stay fast).
fn hash_password_iters(password: &str, iters: u32) -> String {
    let mut salt = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iters, &mut out);
    format!(
        "{}${}${}${}",
        ALGO,
        iters,
        b64e(&salt),
        b64e(&out)
    )
}

/// Constant-time-ish verify: PBKDF2 cost dominates; compare via fixed loop.
fn verify_hash(password: &str, stored: &str) -> bool {
    let Some((iters, salt, expected)) = parse_hash(stored) else {
        return false;
    };
    let mut out = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, iters, &mut out);
    ct_eq(&out, &expected)
}

/// Digest key for the verified-Basic cache — sha256(user\0pass).
fn basic_key(user: &str, pass: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(user.as_bytes());
    h.update([0u8]);
    h.update(pass.as_bytes());
    h.finalize().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Shared auth state held by AppState.
pub struct AuthState {
    pub users: RwLock<Vec<User>>,
    /// Legacy `server.auth` "user:pass" — accepted as admin when set.
    legacy: Option<String>,
    secret: Vec<u8>,
    session_ttl: u64,
    /// TLS enabled → session cookies get the Secure flag.
    pub secure_cookie: bool,
    /// Per-IP failed-login tracking for throttling.
    attempts: Mutex<HashMap<IpAddr, Attempt>>,
    /// Revoked session token ids (jti → expiry). Stateless tokens can't be
    /// un-signed, so logout records the id here until natural expiry.
    revoked: Mutex<HashMap<String, u64>>,
    /// Precomputed hash used to equalize timing for unknown usernames
    /// (lazy — costs one PBKDF2 on first unknown-user attempt).
    dummy_hash: std::sync::OnceLock<String>,
    /// sha256(user\0pass) → (role, expiry_ms) for successful Basic auth.
    /// Raw passwords are never retained — only the digest key.
    basic_ok: Mutex<HashMap<[u8; 32], (Role, u64)>>,
    /// Username portion of the legacy "user:pass" credential — lets
    /// verify_token keep legacy sessions valid without a [[users]] row.
    legacy_user: Option<String>,
}

#[derive(Default)]
struct Attempt {
    fails: u32,
    locked_until_ms: u64,
}

impl AuthState {
    pub fn new(
        users: Vec<User>,
        legacy: Option<String>,
        session_secret: Option<String>,
        session_ttl_secs: Option<u64>,
        secure_cookie: bool,
    ) -> Self {
        let secret = match session_secret {
            Some(s) if !s.is_empty() => {
                // Derive a fixed-size key; never use the raw string.
                let mut h = Sha256::new();
                use sha2::Digest;
                h.update(b"bgflow-session-v1");
                h.update(s.as_bytes());
                h.finalize().to_vec()
            }
            _ => {
                let mut k = vec![0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
                k
            }
        };
        AuthState {
            users: RwLock::new(users),
            legacy_user: legacy
                .as_ref()
                .and_then(|l| l.split_once(':').map(|(u, _)| u.to_string())),
            legacy,
            secret,
            session_ttl: session_ttl_secs.unwrap_or(SESSION_TTL_DEFAULT).max(60),
            secure_cookie,
            attempts: Mutex::new(HashMap::new()),
            revoked: Mutex::new(HashMap::new()),
            dummy_hash: std::sync::OnceLock::new(),
            basic_ok: Mutex::new(HashMap::new()),
        }
    }

    /// Load a persisted session secret, creating one on first run.
    /// Keeps sessions valid across daemon restarts/upgrades without
    /// requiring an explicit `server.session_secret`. Returns None when
    /// the file can't be read or written — caller falls back to an
    /// ephemeral random secret (sessions then die on restart, as before).
    pub fn load_or_create_secret(path: &std::path::Path) -> Option<String> {
        if let Ok(s) = std::fs::read_to_string(path) {
            let s = s.trim();
            if s.len() >= 32 {
                return Some(s.to_string());
            }
        }
        let mut k = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut k);
        let hex: String = k.iter().map(|b| format!("{:02x}", b)).collect();
        if std::fs::write(path, &hex).is_err() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Some(hex)
    }

    /// True when nothing protects the UI/API.
    pub fn is_open(&self) -> bool {
        self.users.read().unwrap().is_empty() && self.legacy.is_none()
    }

    pub fn session_ttl(&self) -> u64 {
        self.session_ttl
    }

    pub fn user_count(&self) -> usize {
        self.users.read().unwrap().len()
    }

    /// Hot-reload users from config (SIGHUP / admin reload).
    /// Invalid entries are skipped with a warning; returns count loaded.
    pub fn reload_users(&self, cfgs: &[UserConfig]) -> usize {
        let mut out = Vec::with_capacity(cfgs.len());
        for u in cfgs {
            match User::from_config(u) {
                Ok(user) => out.push(user),
                Err(e) => tracing::warn!("auth: {} — skipping user", e),
            }
        }
        let n = out.len();
        *self.users.write().unwrap() = out;
        // Password hashes may have changed — drop cached verifications.
        self.basic_ok.lock().unwrap().clear();
        n
    }

    /// Verify HTTP Basic credentials → role. Checks [[users]] first, then
    /// the legacy server.auth string (always admin). Successful verifications
    /// are cached briefly so API clients don't pay PBKDF2 per request;
    /// failures are never cached.
    pub fn check_basic(&self, user: &str, pass: &str) -> Option<Role> {
        let key = basic_key(user, pass);
        let now = now_ms();
        if let Some((r, exp)) = self.basic_ok.lock().unwrap().get(&key) {
            if *exp > now {
                return Some(*r);
            }
        }
        let role = self.check_basic_slow(user, pass);
        if let Some(r) = role {
            let mut c = self.basic_ok.lock().unwrap();
            if c.len() >= BASIC_CACHE_MAX {
                c.clear();
            }
            c.insert(key, (r, now + BASIC_CACHE_MS));
        }
        role
    }

    fn check_basic_slow(&self, user: &str, pass: &str) -> Option<Role> {
        {
            let users = self.users.read().unwrap();
            if let Some(u) = users.iter().find(|u| u.name == user) {
                return verify_hash(pass, &u.pass_hash).then_some(u.role);
            }
        }
        if let Some(legacy) = &self.legacy {
            // legacy format "user:pass" — compare whole credential string.
            let cred = format!("{}:{}", user, pass);
            if ct_eq(cred.as_bytes(), legacy.as_bytes()) {
                return Some(Role::Admin);
            }
        }
        None
    }

    /// Basic-auth attempt with the same per-IP throttling as `login` —
    /// the middleware path must not bypass lockout, or an attacker could
    /// burn a PBKDF2 per request forever.
    pub fn check_basic_ip(&self, ip: IpAddr, user: &str, pass: &str) -> Option<Role> {
        if self.throttle_locked(ip) {
            return None;
        }
        let role = self.check_basic(user, pass);
        self.throttle_record(ip, role.is_some());
        role
    }

    fn throttle_locked(&self, ip: IpAddr) -> bool {
        let now = now_ms();
        let mut att = self.attempts.lock().unwrap();
        // Opportunistic GC so the map can't grow unboundedly.
        if att.len() > 10_000 {
            att.retain(|_, a| a.locked_until_ms > now || a.fails < MAX_FAILS);
        }
        att.get(&ip).map(|a| a.locked_until_ms > now).unwrap_or(false)
    }

    fn throttle_record(&self, ip: IpAddr, success: bool) {
        let now = now_ms();
        let mut att = self.attempts.lock().unwrap();
        let a = att.entry(ip).or_default();
        if success {
            a.fails = 0;
            a.locked_until_ms = 0;
        } else {
            a.fails += 1;
            if a.fails >= MAX_FAILS {
                let over = (a.fails - MAX_FAILS).min(10);
                let secs = (LOCKOUT_BASE_SECS << over).min(LOCKOUT_MAX_SECS);
                a.locked_until_ms = now + secs * 1000;
            }
        }
    }

    /// Attempt a password login for `user`. Enforces per-IP throttling.
    /// Returns the role on success, None on failure (bad creds or locked).
    pub fn login(&self, ip: IpAddr, user: &str, pass: &str) -> Option<Role> {
        if self.throttle_locked(ip) {
            return None; // locked out
        }

        let role = {
            let users = self.users.read().unwrap();
            match users.iter().find(|u| u.name == user) {
                Some(u) => verify_hash(pass, &u.pass_hash).then_some(u.role),
                // Unknown user: burn equivalent CPU, never reveal existence.
                None => {
                    let dummy = self
                        .dummy_hash
                        .get_or_init(|| hash_password("bgflow-dummy"));
                    let _ = verify_hash(pass, dummy);
                    None
                }
            }
        };
        // Legacy auth also works via the login form.
        let role = role.or_else(|| self.check_basic(user, pass));

        self.throttle_record(ip, role.is_some());
        role
    }

    /// Issue a signed session token for user+role.
    pub fn issue_token(&self, user: &str, role: Role) -> String {
        let payload = format!(
            "v1|{}|{}|{}|{}",
            user,
            role.as_str(),
            now_unix() + self.session_ttl,
            rand_suffix()
        );
        let p = b64url_e(payload.as_bytes());
        let sig = self.sign(p.as_bytes());
        format!("{}.{}", p, sig)
    }

    /// Parse + verify a session token → (user, role, secs_left, jti, exp).
    /// Returns None for bad signature, malformed payload, or expiry.
    fn parse_token(&self, token: &str) -> Option<(String, Role, u64, String, u64)> {
        let (p, sig) = token.split_once('.')?;
        let expect = self.sign(p.as_bytes());
        if !ct_eq(sig.as_bytes(), expect.as_bytes()) {
            return None;
        }
        let payload = String::from_utf8(b64url_d(p)?).ok()?;
        let mut it = payload.split('|');
        if it.next()? != "v1" {
            return None;
        }
        let user = it.next()?.to_string();
        let role = match it.next()? {
            "admin" => Role::Admin,
            "viewer" => Role::Viewer,
            _ => return None,
        };
        let exp: u64 = it.next()?.parse().ok()?;
        let left = exp.saturating_sub(now_unix());
        if left == 0 {
            return None;
        }
        let jti = it.next().unwrap_or("").to_string();
        Some((user, role, left, jti, exp))
    }

    /// Verify a session token → (user, role, seconds_left).
    /// Rejects revoked (logged-out) token ids and sessions whose user
    /// was removed by a config reload — deleted accounts lose access
    /// immediately rather than at token expiry.
    pub fn verify_token(&self, token: &str) -> Option<(String, Role, u64)> {
        let (u, r, left, jti, _) = self.parse_token(token)?;
        if !jti.is_empty() && self.revoked.lock().unwrap().contains_key(&jti) {
            return None;
        }
        let known = {
            let users = self.users.read().unwrap();
            users.iter().any(|x| x.name == u)
                || self.legacy_user.as_deref() == Some(u.as_str())
        };
        if !known {
            return None;
        }
        Some((u, r, left))
    }

    /// Revoke a session token (logout). Verifies the signature first so
    /// arbitrary ids can't be injected; records the jti until expiry.
    /// No-op for invalid/expired tokens.
    pub fn revoke_token(&self, token: &str) {
        let Some((_, _, _, jti, exp)) = self.parse_token(token) else {
            return;
        };
        if jti.is_empty() {
            return;
        }
        let mut m = self.revoked.lock().unwrap();
        if m.len() > 4096 {
            let now = now_unix();
            m.retain(|_, e| *e > now);
        }
        m.insert(jti, exp);
    }

    fn sign(&self, data: &[u8]) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.secret).expect("hmac key");
        mac.update(data);
        b64url_e(&mac.finalize().into_bytes())
    }

    /// Extract identity from a request's Cookie or Authorization header.
    /// Used by the middleware and /auth/me.
    pub fn identity_from_headers(
        &self,
        ip: IpAddr,
        cookie: Option<&str>,
        authz: Option<&str>,
    ) -> Option<(String, Role)> {
        // Session cookie first.
        if let Some(c) = cookie {
            for part in c.split(';') {
                let part = part.trim();
                if let Some(tok) = part.strip_prefix("bgflow_session=") {
                    if let Some((u, r, _)) = self.verify_token(tok) {
                        return Some((u, r));
                    }
                }
            }
        }
        // HTTP Basic for API clients — throttled per-IP like /auth/login
        // so credential brute-force can't bypass the lockout.
        if let Some(v) = authz {
            if let Some(b64) = v.strip_prefix("Basic ") {
                if let Some(bytes) = b64_decode(b64) {
                    if let Ok(s) = String::from_utf8(bytes) {
                        if let Some((u, p)) = s.split_once(':') {
                            if let Some(r) = self.check_basic_ip(ip, u, p) {
                                return Some((u.to_string(), r));
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Paths any authenticated role may access; everything else needs admin.
    /// (Viewer still gets all GET data endpoints.)
    pub fn requires_admin(path: &str) -> bool {
        path.starts_with("/api/v1/admin/")
            || path.starts_with("/api/v1/exporters/")
            || path == "/api/v1/config"
            || path == "/api/v1/enrichers"
    }

    /// Viewer role may only use safe methods.
    pub fn method_allowed(role: Role, method: &str) -> bool {
        role.is_admin() || matches!(method, "GET" | "HEAD" | "OPTIONS")
    }
}

fn rand_suffix() -> String {
    let mut b = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    b64url_e(&b)
}

/// Minimal base64 decode for the Basic auth path (standard alphabet).
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

// Keep Arc import used (AuthState is always Arc'd by callers).
#[allow(dead_code)]
type _ArcAuth = Arc<AuthState>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test hashes use the parse_hash floor (10k iters) — ~60× faster than
    /// production in debug builds; verify_hash honors stored iters.
    const TEST_ITERS: u32 = 10_000;

    fn test_user() -> UserConfig {
        UserConfig {
            name: "alice".into(),
            password_hash: hash_password_iters("s3cret!", TEST_ITERS),
            role: Role::Admin,
        }
    }

    fn state() -> AuthState {
        let u = User::from_config(&test_user()).unwrap();
        AuthState::new(vec![u], None, Some("test-secret".into()), None, false)
    }

    #[test]
    fn hash_roundtrip() {
        let h = hash_password_iters("hunter2", TEST_ITERS);
        assert!(h.starts_with("pbkdf2-sha256$"));
        assert!(verify_hash("hunter2", &h));
        assert!(!verify_hash("hunter3", &h));
        assert!(!verify_hash("hunter2", "garbage"));
        assert!(!verify_hash("hunter2", "pbkdf2-sha256$1$AAAA$BBBB")); // too few iters
    }

    #[test]
    fn user_validation() {
        let mut bad = test_user();
        bad.name = "bad name!".into();
        assert!(User::from_config(&bad).is_err());
        let mut badh = test_user();
        badh.password_hash = "nope".into();
        assert!(User::from_config(&badh).is_err());
    }

    #[test]
    fn login_and_roles() {
        let st = state();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(st.login(ip, "alice", "s3cret!"), Some(Role::Admin));
        assert_eq!(st.login(ip, "alice", "wrong"), None);
        assert_eq!(st.login(ip, "ghost", "s3cret!"), None);
        // Basic auth path.
        assert_eq!(st.check_basic("alice", "s3cret!"), Some(Role::Admin));
        assert_eq!(st.check_basic("alice", "no"), None);
    }

    #[test]
    fn token_roundtrip_and_tamper() {
        let st = state();
        let tok = st.issue_token("alice", Role::Viewer);
        let (u, r, left) = st.verify_token(&tok).unwrap();
        assert_eq!(u, "alice");
        assert_eq!(r, Role::Viewer);
        assert!(left > 80_000);
        // Tampered signature rejected.
        let mut bad = tok.clone();
        bad.replace_range(bad.len() - 2.., "xx");
        assert!(st.verify_token(&bad).is_none());
        // Garbage rejected.
        assert!(st.verify_token("not-a-token").is_none());
    }

    #[test]
    fn viewer_permissions() {
        assert!(AuthState::method_allowed(Role::Viewer, "GET"));
        assert!(!AuthState::method_allowed(Role::Viewer, "POST"));
        assert!(AuthState::method_allowed(Role::Admin, "POST"));
        assert!(AuthState::requires_admin("/api/v1/admin/reload"));
        assert!(AuthState::requires_admin("/api/v1/config"));
        assert!(AuthState::requires_admin("/api/v1/enrichers"));
        assert!(!AuthState::requires_admin("/api/v1/flows"));
    }

    #[test]
    fn legacy_auth_admin() {
        let st = AuthState::new(vec![], Some("admin:pw".into()), None, None, false);
        assert_eq!(st.check_basic("admin", "pw"), Some(Role::Admin));
        assert_eq!(st.check_basic("admin", "no"), None);
        assert!(!st.is_open());
    }

    #[test]
    fn logout_revokes_token() {
        let st = state();
        let tok = st.issue_token("alice", Role::Admin);
        assert!(st.verify_token(&tok).is_some());
        st.revoke_token(&tok);
        assert!(st.verify_token(&tok).is_none());
        // Other tokens unaffected; forged revocations rejected.
        let tok2 = st.issue_token("alice", Role::Viewer);
        assert!(st.verify_token(&tok2).is_some());
        st.revoke_token("forged.token");
        assert!(st.verify_token(&tok2).is_some());
    }

    #[test]
    fn brute_force_lockout() {
        let st = state();
        let ip: IpAddr = "10.0.0.9".parse().unwrap();
        for _ in 0..5 {
            assert_eq!(st.login(ip, "alice", "bad"), None);
        }
        // 6th+ attempts are locked out even with the right password.
        assert_eq!(st.login(ip, "alice", "s3cret!"), None);
        // A different IP is unaffected.
        let ip2: IpAddr = "10.0.0.10".parse().unwrap();
        assert_eq!(st.login(ip2, "alice", "s3cret!"), Some(Role::Admin));
    }

    #[test]
    fn session_secret_persistence() {
        // Same configured secret → tokens verify across AuthState instances.
        let mk = || AuthState::new(
            vec![User::from_config(&test_user()).unwrap()],
            None,
            Some("same".into()),
            None,
            false,
        );
        let st1 = mk();
        let st2 = mk();
        let tok = st1.issue_token("alice", Role::Admin);
        assert!(st2.verify_token(&tok).is_some());
    }

    #[test]
    fn deleted_user_session_dies() {
        let st = state();
        let tok = st.issue_token("alice", Role::Admin);
        assert!(st.verify_token(&tok).is_some());
        // Config reload dropping the user revokes access immediately —
        // the token signature is still valid but the account is gone.
        st.reload_users(&[]);
        assert!(st.verify_token(&tok).is_none());
    }

    #[test]
    fn basic_throttle_locks_ip() {
        let st = state();
        let ip: IpAddr = "10.0.0.20".parse().unwrap();
        for _ in 0..5 {
            assert_eq!(st.check_basic_ip(ip, "alice", "bad"), None);
        }
        // Locked out — even the right password is refused for this IP.
        assert_eq!(st.check_basic_ip(ip, "alice", "s3cret!"), None);
        // Other IPs unaffected.
        let ip2: IpAddr = "10.0.0.21".parse().unwrap();
        assert_eq!(st.check_basic_ip(ip2, "alice", "s3cret!"), Some(Role::Admin));
    }

    #[test]
    fn basic_cred_cache_and_reload() {
        let st = state();
        // Repeat calls hit the verified-credential cache — same result.
        assert_eq!(st.check_basic("alice", "s3cret!"), Some(Role::Admin));
        assert_eq!(st.check_basic("alice", "s3cret!"), Some(Role::Admin));
        // reload_users clears the cache; verification still succeeds.
        st.reload_users(&[test_user()]);
        assert_eq!(st.check_basic("alice", "s3cret!"), Some(Role::Admin));
        // Wrong password is never cached as a success.
        assert_eq!(st.check_basic("alice", "wrong"), None);
    }
}

