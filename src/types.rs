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
    /// Passkey: WebAuthn PRF-derived secp256k1 key. A synced passkey gives the same key on devices
    /// using this crate with the same RP ID.
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
    /// `event_json` takes `kind`, `tags`, `content` and `created_at`, on every method. An absent
    /// `pubkey` is filled in with the session key. A `pubkey` that differs from it, or an `id` that
    /// does not match the fields, is refused before anything reaches a signer.
    ///
    /// An event from a remote signer is returned only if its `pubkey` is the session key, its
    /// `kind`, `tags`, `content` and `created_at` equal the request, and its id and signature
    /// verify. The returned JSON is that verified event, without any extra fields the signer added.
    ///
    /// # Errors
    ///
    /// Read-only sessions return an error. Also, returns an error if signing fails. A closed
    /// bunker session returns [`NostrAuthError::BunkerSessionClosed`]. A returned event from
    /// another key returns [`NostrAuthError::SignerKeyMismatch`], usually after an account switch
    /// in the extension. Other refused requests and returns are
    /// [`NostrAuthError::SigningFailed`], and malformed input is
    /// [`NostrAuthError::Serialization`]. Match the variant, not the text.
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

    /// NIP-44 encrypt `plaintext` for `peer`, the same call on every method. Passkey, Ncryptsec and
    /// `RawNsec` use `nostr`'s NIP-44 v2 with the key in memory and finish without suspending,
    /// including on a server. Extension and Bunker ask their signer, and need the browser.
    ///
    /// # Errors
    ///
    /// - [`NostrAuthError::EncryptionUnavailable`]: a read-only session with any peer, or an
    ///   Extension or Bunker session on a server.
    /// - [`NostrAuthError::InvalidPublicKey`]: `peer` is not on the curve, on every other method and
    ///   before anything reaches a signer. From an extension it can also mean `getPublicKey`
    ///   returned a malformed or off-curve key.
    /// - [`NostrAuthError::EncryptionFailed`]: a key session's failure, including empty plaintext,
    ///   or a signer's refusal or malformed response.
    /// - [`NostrAuthError::ExtensionNotFound`], [`NostrAuthError::ExtensionRejected`] and
    ///   [`NostrAuthError::SignerKeyMismatch`]: see [`Nip07Handle::nip44_encrypt`].
    /// - [`NostrAuthError::BunkerSessionClosed`], [`NostrAuthError::BunkerTimeout`],
    ///   [`NostrAuthError::BunkerAuthRequired`] and [`NostrAuthError::BunkerConnectionFailed`]: see
    ///   [`BunkerSession::nip44_encrypt`].
    pub async fn nip44_encrypt(
        &self,
        peer: &PublicKey,
        plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        match self {
            Self::Extension(h) => h.nip44_encrypt(peer, plaintext).await,
            Self::Bunker(s) => s.nip44_encrypt(peer, plaintext).await,
            Self::Passkey(s) => s.nip44_encrypt(peer, plaintext),
            Self::ReadOnly(_) => Err(NostrAuthError::EncryptionUnavailable),
            Self::Ncryptsec(s) => s.nip44_encrypt(peer, plaintext),
            #[cfg(feature = "insecure_nsec_input")]
            Self::RawNsec(s) => s.nip44_encrypt(peer, plaintext),
        }
    }

    /// NIP-44 decrypt `ciphertext` from `peer`. See [`Self::nip44_encrypt`].
    ///
    /// # Errors
    ///
    /// The same as [`Self::nip44_encrypt`]. On a key session a wrong key or bad payload is
    /// [`NostrAuthError::EncryptionFailed`].
    pub async fn nip44_decrypt(
        &self,
        peer: &PublicKey,
        ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        match self {
            Self::Extension(h) => h.nip44_decrypt(peer, ciphertext).await,
            Self::Bunker(s) => s.nip44_decrypt(peer, ciphertext).await,
            Self::Passkey(s) => s.nip44_decrypt(peer, ciphertext),
            Self::ReadOnly(_) => Err(NostrAuthError::EncryptionUnavailable),
            Self::Ncryptsec(s) => s.nip44_decrypt(peer, ciphertext),
            #[cfg(feature = "insecure_nsec_input")]
            Self::RawNsec(s) => s.nip44_decrypt(peer, ciphertext),
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

impl core::fmt::Debug for AuthResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let variant = match self {
            Self::Extension(_) => "Extension",
            Self::Bunker(_) => "Bunker",
            Self::Passkey(_) => "Passkey",
            Self::ReadOnly(_) => "ReadOnly",
            Self::Ncryptsec(_) => "Ncryptsec",
            #[cfg(feature = "insecure_nsec_input")]
            Self::RawNsec(_) => "RawNsec",
        };
        f.debug_struct(variant)
            .field("public_key", &self.public_key())
            .finish()
    }
}

/// What gets written to localStorage.
///
/// Never contains the user's Nostr identity secret key. **Does** contain a disposable,
/// revocable NIP-46 pairing key (`bunker_client_secret_hex`) when the active session is
/// a bunker connection — see the "Session Restore" section in the README for the exact
/// risk model.
///
/// `Debug` prints `bunker_uri` and `bunker_client_secret_hex` as `<redacted>`. Serde output carries
/// them in full.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl core::fmt::Debug for PersistedSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        const REDACTED: &str = "<redacted>";
        f.debug_struct("PersistedSession")
            .field("public_key_hex", &self.public_key_hex)
            .field("method", &self.method)
            // A public field decoded from localStorage: nothing enforces that it is secret-free.
            .field("bunker_uri", &self.bunker_uri.as_ref().map(|_| REDACTED))
            .field(
                "bunker_client_secret_hex",
                &self.bunker_client_secret_hex.as_ref().map(|_| REDACTED),
            )
            .field("passkey_credential_id", &self.passkey_credential_id)
            .finish()
    }
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

impl PersistedMethod {
    /// The login method a stored session of this kind needs to be allowed.
    pub(crate) const fn login_method(&self) -> LoginMethod {
        match self {
            Self::Extension => LoginMethod::Extension,
            Self::Bunker => LoginMethod::Bunker,
            Self::Passkey => LoginMethod::Passkey,
            Self::ReadOnly => LoginMethod::ReadOnly,
        }
    }
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
    /// WebAuthn relying party ID (default: `window.location.hostname`), with no `https://` prefix.
    ///
    /// Set it to share credentials across subdomains, e.g. `"myapp.com"`. It must equal the host or
    /// be a registrable-domain suffix of it, not a public suffix.
    ///
    /// Every ceremony sends it, so changing it strands credentials made under the old value,
    /// including ones made under the hostname before it was set. Reverting the config recovers them.
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
    /// `window.nostr` or the requested method was not found.
    #[error("Browser extension (window.nostr) not found")]
    ExtensionNotFound,
    /// The extension rejected the request (e.g. user denied permission).
    #[error("Extension request rejected: {0}")]
    ExtensionRejected(String),
    /// A public key could not be parsed or is not on the curve.
    ///
    /// As `NostrAuthContext::restore_error` it has two causes, told apart only by text, which is
    /// not API: stored data that can never restore, or an extension currently returning no valid
    /// key, where the same session restores once fixed. It does not prove the session is dead.
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
    /// The signer used a different key than this session, usually after an account switch in the extension: two valid keys that differ; a signer returning no valid key is reported as that signer's parse failure. Log in again to switch. As `NostrAuthContext::restore_error`, the stored session is kept and retried next time, so switching the signer back to its key restores it.
    #[error("Signer is using a different account than this session. Log in again to switch.")]
    SignerKeyMismatch,
    /// The stored session's login method is no longer in `NostrAuthConfig::allowed_methods`. The session is kept, and restores if the method is allowed again.
    #[error("This session's login method is no longer allowed")]
    RestoreMethodNotAllowed,
    /// A WebAuthn / passkey operation failed.
    #[error("Passkey operation failed: {0}")]
    PasskeyFailed(String),
    /// The browser or authenticator does not support the WebAuthn PRF extension.
    #[error("This browser or authenticator does not support the WebAuthn PRF extension")]
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
    /// This session cannot run NIP-44. In the browser, [`AuthResult::can_sign`] being false predicts it.
    #[error(
        "This session cannot encrypt or decrypt: it is read-only, or its signer is only reachable in the browser"
    )]
    EncryptionUnavailable,
    /// NIP-44 failed, in either direction. The text may come from the signer. On a key session it can
    /// give a byte position within a plaintext, never its bytes.
    #[error("NIP-44 encryption or decryption failed: {0}")]
    EncryptionFailed(String),
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

    #[test]
    fn persisted_session_debug_redacts_secrets() {
        const SENTINEL: &str = "SENTINELSECRET";
        let full = PersistedSession {
            public_key_hex: "ab".repeat(32),
            method: PersistedMethod::Bunker,
            bunker_uri: Some(format!("bunker://x?secret={SENTINEL}")),
            bunker_client_secret_hex: Some(SENTINEL.to_owned()),
            passkey_credential_id: Some("credential".to_owned()),
        };
        for text in [format!("{full:?}"), format!("{full:#?}")] {
            assert!(!text.contains(SENTINEL), "{text}");
            assert_eq!(text.matches("<redacted>").count(), 2, "{text}");
            assert!(text.contains(&"ab".repeat(32)), "{text}");
            assert!(text.contains("Bunker"), "{text}");
            assert!(text.contains("credential"), "{text}");
        }
        assert!(format!("{full:?}").contains(r#"bunker_uri: Some("<redacted>")"#));
        let empty = PersistedSession {
            bunker_uri: None,
            bunker_client_secret_hex: None,
            ..full
        };
        let text = format!("{empty:?}");
        assert!(text.contains("bunker_uri: None"), "{text}");
        assert!(text.contains("bunker_client_secret_hex: None"), "{text}");
    }

    #[test]
    #[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
    fn debug_prints_variant_and_public_key_only() {
        use crate::signers::{PasskeySession, RawKeySession};
        let keys = Keys::new(
            nostr::key::SecretKey::from_hex(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
        );
        let hex = keys.public_key().to_hex();
        let check = |name: &str, auth: &AuthResult| {
            assert_eq!(
                format!("{auth:?}"),
                format!("{name} {{ public_key: PublicKey({hex}) }}")
            );
            assert_eq!(
                format!("{auth:#?}"),
                format!("{name} {{\n    public_key: PublicKey({hex}),\n}}")
            );
        };
        #[cfg(feature = "insecure_nsec_input")]
        check(
            "RawNsec",
            &AuthResult::RawNsec(RawKeySession::for_tests(keys.clone())),
        );
        let cases = [
            (
                "Extension",
                AuthResult::Extension(Nip07Handle {
                    public_key: keys.public_key(),
                }),
            ),
            (
                "ReadOnly",
                AuthResult::ReadOnly(ReadOnlyHandle {
                    public_key: keys.public_key(),
                }),
            ),
            (
                "Ncryptsec",
                AuthResult::Ncryptsec(RawKeySession::for_tests(keys.clone())),
            ),
            (
                "Passkey",
                AuthResult::Passkey(PasskeySession::for_tests(keys, vec![7, 8, 9])),
            ),
        ];
        for (name, auth) in &cases {
            check(name, auth);
        }
    }
}
