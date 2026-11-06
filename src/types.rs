use nostr::key::PublicKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::signers::{BunkerSession, Nip07Handle, PasskeySession, RawKeySession, ReadOnlyHandle};

/// Result of a successful authentication attempt.
#[derive(Clone)]
#[non_exhaustive]
pub enum AuthResult {
    /// NIP-07: browser extension (Alby, nos2x, Nostr KeyX, etc.)
    Extension(Nip07Handle),
    /// NIP-46: remote bunker signer (also covers Amber via NIP-46 mode)
    Bunker(Box<BunkerSession>),
    /// Passkey: WebAuthn PRF-derived secp256k1 key, syncs via iCloud Keychain / platform
    Passkey(PasskeySession),
    /// Read-only: public key only, no signing capability
    ReadOnly(ReadOnlyHandle),
    /// NIP-49: ncryptsec password-decrypted key (in-memory only)
    Ncryptsec(RawKeySession),
    /// Raw nsec paste: in-memory key (only with `insecure_nsec_input` feature)
    #[cfg(feature = "insecure_nsec_input")]
    RawNsec(RawKeySession),
}

impl AuthResult {
    /// Returns the public key for any auth variant.
    pub fn public_key(&self) -> PublicKey {
        match self {
            Self::Extension(h) => h.public_key,
            Self::Bunker(s) => s.public_key,
            Self::Passkey(s) => s.public_key,
            Self::ReadOnly(h) => h.public_key,
            Self::Ncryptsec(s) => s.public_key,
            #[cfg(feature = "insecure_nsec_input")]
            Self::RawNsec(s) => s.public_key,
        }
    }

    /// Sign a Nostr event using whichever backend is active.
    ///
    /// All backends present a uniform async interface. Sync backends (Passkey, Ncryptsec)
    /// return immediately without suspending.
    ///
    /// # Errors
    ///
    /// Read-only sessions return an error. Also, returns an error if signing fails.
    pub async fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        match self {
            Self::Extension(h) => h.sign_event(event_json).await,
            Self::Bunker(s) => s.sign_event(event_json).await,
            Self::Passkey(s) => s.sign_event(event_json),
            Self::ReadOnly(_) => Err(NostrAuthError::SigningFailed(
                "Read-only session cannot sign events".into(),
            )),
            Self::Ncryptsec(s) => s.sign_event(event_json),
            #[cfg(feature = "insecure_nsec_input")]
            Self::RawNsec(s) => s.sign_event(event_json),
        }
    }

    /// Close a bunker session for good, for every clone. Other variants hold no connection.
    pub(crate) fn close_session(&self) {
        if let Self::Bunker(s) = self {
            s.close();
        }
    }

    /// Returns `true` if this session can sign events.
    ///
    /// `false` only for `ReadOnly` sessions.
    pub const fn can_sign(&self) -> bool {
        !matches!(self, Self::ReadOnly(_))
    }

    /// Human-readable name of the authentication method.
    ///
    /// Useful for display: "Logged in via Browser Extension".
    pub const fn method_name(&self) -> &'static str {
        self.login_method().name()
    }

    /// The `LoginMethod` that produces this result.
    const fn login_method(&self) -> LoginMethod {
        match self {
            Self::Extension(_) => LoginMethod::Extension,
            Self::Bunker(_) => LoginMethod::Bunker,
            Self::Passkey(_) => LoginMethod::Passkey,
            Self::ReadOnly(_) => LoginMethod::ReadOnly,
            Self::Ncryptsec(_) => LoginMethod::Ncryptsec,
            #[cfg(feature = "insecure_nsec_input")]
            Self::RawNsec(_) => LoginMethod::RawNsec,
        }
    }

    /// Build a `PersistedSession` for localStorage (never stores the user's identity key).
    pub fn to_persisted_session(&self) -> Option<PersistedSession> {
        match self {
            Self::Extension(h) => Some(PersistedSession {
                public_key_hex: h.public_key.to_hex(),
                method: PersistedMethod::Extension,
                bunker_uri: None,
                bunker_client_secret_hex: None,
                passkey_credential_id: None,
            }),
            Self::Bunker(s) => Some(PersistedSession {
                public_key_hex: s.public_key.to_hex(),
                method: PersistedMethod::Bunker,
                // Already secret-free — see `BunkerSession::connect_with_keys`.
                bunker_uri: Some(s.bunker_uri.clone()),
                bunker_client_secret_hex: Some(s.client_secret_hex()),
                passkey_credential_id: None,
            }),
            Self::Passkey(s) => Some(PersistedSession {
                public_key_hex: s.public_key.to_hex(),
                method: PersistedMethod::Passkey,
                bunker_uri: None,
                bunker_client_secret_hex: None,
                passkey_credential_id: Some(base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    &s.credential_id,
                )),
            }),
            Self::ReadOnly(h) => Some(PersistedSession {
                public_key_hex: h.public_key.to_hex(),
                method: PersistedMethod::ReadOnly,
                bunker_uri: None,
                bunker_client_secret_hex: None,
                passkey_credential_id: None,
            }),
            // ncryptsec and raw nsec: key is not persisted (no safe way to store it)
            Self::Ncryptsec(_) => None,
            #[cfg(feature = "insecure_nsec_input")]
            Self::RawNsec(_) => None,
        }
    }
}

/// What gets written to localStorage.
///
/// Never contains the user's Nostr identity secret key. **Does** contain a disposable,
/// revocable NIP-46 pairing key (`bunker_client_secret_hex`) when the active session is
/// a bunker connection — see the "Session Restore" section in the README for the exact
/// risk model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PersistedSession {
    /// Authenticated public key as lowercase hex.
    pub public_key_hex: String,
    /// Which login method was used.
    pub method: PersistedMethod,
    /// NIP-46: secret-stripped `bunker://` URI (remote pubkey + relays only) for reconnection.
    pub bunker_uri: Option<String>,
    /// NIP-46: hex secret of the local pairing keypair used to reconnect without the
    /// bunker's one-time secret. Sensitive (bearer-token-equivalent) but is never the
    /// user's Nostr identity key — see `BunkerSession::reconnect` docs.
    pub bunker_client_secret_hex: Option<String>,
    /// Passkey: base64url credential ID — used to call `credentials.get()`
    pub passkey_credential_id: Option<String>,
}

/// Which login method was used to establish a [`PersistedSession`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PersistedMethod {
    /// NIP-07 browser extension.
    Extension,
    /// NIP-46 remote bunker.
    Bunker,
    /// WebAuthn passkey.
    Passkey,
    /// Read-only public key.
    ReadOnly,
}

/// Which login methods to show in the modal.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoginMethod {
    /// NIP-07 browser extension.
    Extension,
    /// NIP-46 remote bunker.
    Bunker,
    /// WebAuthn passkey.
    Passkey,
    /// Read-only public key (no signing).
    ReadOnly,
    /// NIP-49 ncryptsec password-decrypted key.
    Ncryptsec,
    /// Raw nsec paste (requires `insecure_nsec_input` feature).
    #[cfg(feature = "insecure_nsec_input")]
    RawNsec,
}

impl LoginMethod {
    /// Returns all enabled login methods in display order.
    pub fn all() -> Vec<Self> {
        vec![
            Self::Extension,
            Self::Bunker,
            Self::Passkey,
            Self::ReadOnly,
            Self::Ncryptsec,
            #[cfg(feature = "insecure_nsec_input")]
            Self::RawNsec,
        ]
    }

    /// Human-readable name for this login method.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Extension => "Browser Extension",
            Self::Bunker => "Nostr Connect",
            Self::Passkey => "Passkey",
            Self::ReadOnly => "Read-Only",
            Self::Ncryptsec => "Encrypted Key",
            #[cfg(feature = "insecure_nsec_input")]
            Self::RawNsec => "Secret Key",
        }
    }
}

/// Configuration for [`crate::modal::NostrAuthModal`] and [`crate::context::NostrAuthProvider`].
///
/// Construct with struct update syntax from [`Default`]:
/// ```rust,ignore
/// let config = NostrAuthConfig { rp_id: Some("myapp.com".to_owned()), ..Default::default() };
/// ```
#[derive(Clone)]
#[expect(
    clippy::exhaustive_structs,
    reason = "consumers construct this with struct update syntax"
)]
pub struct NostrAuthConfig {
    /// Persist session to localStorage after login (default: `true`)
    pub persist_session: bool,
    /// localStorage key (default: `"leptos_nostr_auth_session"`)
    pub storage_key: String,
    /// Close modal on backdrop click (default: `true`)
    pub close_on_backdrop_click: bool,
    /// Close modal on Escape key (default: `true`)
    pub close_on_escape: bool,
    /// Which login methods to expose (default: all)
    pub allowed_methods: Vec<LoginMethod>,
    /// NIP-46 timeout in seconds (default: `30`), applied per relay and per step: each socket open
    /// and each request gets the full value. A request whose signer sends an approval link waits
    /// one extra 300 s, only while a mounted [`crate::modal::NostrAuthModal`] can show the link.
    ///
    /// This is not a limit on a whole call. With `n` relays, at most 5, and this value as `T`, the
    /// most a call can take is: `(n+1)T`, plus 300 s with an approval link, for a call that
    /// reconnects; `2T`, plus 300 s with a link, for a call waiting on another call's reconnect;
    /// `(2n+1)T + 600 s` for login; `2nT + 300 s` for restore.
    pub bunker_timeout_secs: u32,
    /// WebAuthn relying party ID — MUST match your domain (default: `window.location.hostname`)
    ///
    /// **Required for passkey to work.** Passkeys are scoped to an RP ID.
    /// Set this to your domain, e.g. `"myapp.com"` (no `https://` prefix).
    pub rp_id: Option<String>,
    /// WebAuthn relying party display name (default: `"Nostr App"`)
    pub rp_name: String,
}

impl Default for NostrAuthConfig {
    fn default() -> Self {
        Self {
            persist_session: true,
            storage_key: "leptos_nostr_auth_session".to_owned(),
            close_on_backdrop_click: true,
            close_on_escape: true,
            allowed_methods: LoginMethod::all(),
            bunker_timeout_secs: 30,
            rp_id: None,
            rp_name: "Nostr App".to_owned(),
        }
    }
}

/// Errors returned by authentication operations.
#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum NostrAuthError {
    /// `window.nostr` was not found — no NIP-07 extension installed.
    #[error("Browser extension (window.nostr) not found")]
    ExtensionNotFound,
    /// The extension rejected the request (e.g. user denied permission).
    #[error("Extension request rejected: {0}")]
    ExtensionRejected(String),
    /// The supplied public key string could not be parsed.
    #[error("Invalid public key format: {0}")]
    InvalidPublicKey(String),
    /// The supplied bunker URI was malformed.
    #[error("Invalid bunker URI: {0}")]
    InvalidBunkerUri(String),
    /// The WebSocket connection to the bunker failed.
    #[error("Bunker connection failed: {0}")]
    BunkerConnectionFailed(String),
    /// The bunker did not respond within the configured timeout.
    #[error("Bunker connection timed out")]
    BunkerTimeout,
    /// The remote signer asked for approval through a link, and no mounted
    /// [`crate::modal::NostrAuthModal`] could show it. The link is never part of this error.
    #[error(
        "Remote signer requires link approval, but no NostrAuthModal is mounted to show the link"
    )]
    BunkerAuthRequired,
    /// This session was closed for good. Retrying cannot succeed; read the current session from `NostrAuthContext::auth`.
    #[error("Bunker session closed by logout or replacement")]
    BunkerSessionClosed,
    /// A WebAuthn / passkey operation failed.
    #[error("Passkey operation failed: {0}")]
    PasskeyFailed(String),
    /// The browser does not support the WebAuthn PRF extension.
    #[error("Browser does not support WebAuthn PRF extension")]
    PasskeyNotSupported,
    /// The supplied ncryptsec string was malformed.
    #[error("Invalid ncryptsec string: {0}")]
    InvalidNcryptsec(String),
    /// The password supplied for ncryptsec decryption was incorrect.
    #[error("Wrong password for ncryptsec")]
    WrongPassword,
    /// The supplied secret key string was invalid.
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),
    /// Event signing failed.
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    /// JSON serialization/deserialization failed.
    #[error("Serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::key::Keys;

    #[test]
    fn method_names_are_stable() {
        assert_eq!(LoginMethod::Extension.name(), "Browser Extension");
        assert_eq!(LoginMethod::Bunker.name(), "Nostr Connect");
        assert_eq!(LoginMethod::Passkey.name(), "Passkey");
        assert_eq!(LoginMethod::ReadOnly.name(), "Read-Only");
        assert_eq!(LoginMethod::Ncryptsec.name(), "Encrypted Key");
        #[cfg(feature = "insecure_nsec_input")]
        assert_eq!(LoginMethod::RawNsec.name(), "Secret Key");
        let public_key = Keys::generate().public_key();
        let ext = AuthResult::Extension(Nip07Handle { public_key });
        assert_eq!(ext.method_name(), "Browser Extension");
        let ro = AuthResult::ReadOnly(ReadOnlyHandle { public_key });
        assert_eq!(ro.method_name(), "Read-Only");
    }
}
