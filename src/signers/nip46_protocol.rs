use core::cell::RefCell;
use core::fmt;
use std::collections::HashMap;
use std::rc::Rc;

use nostr::event::{Event, EventId, FinalizeEvent, Kind, Tag, UnsignedEvent};
use nostr::filter::Filter;
use nostr::key::{Keys, PublicKey};
use nostr::message::{ClientMessage, RelayMessage, SubscriptionId};
use nostr::nips::nip44;
use nostr::nips::nip46::{
    NostrConnectMessage, NostrConnectMethod, NostrConnectRequest, NostrConnectUri, ResponseResult,
};
use nostr::types::url::RelayUrlScheme;
use nostr::types::{RelayUrl, Timestamp, Url};
use serde::Deserialize;

use super::{is_nip44_payload, sanitize_remote_text};
use crate::types::NostrAuthError;

/// Most relays accepted from one URI, counted after de-duplication.
pub(super) const MAX_BUNKER_RELAYS: usize = 5;
/// Extra wait granted once to a request whose link a mounted modal can show.
pub(super) const AUTH_URL_TIMEOUT_SECS: u32 = 300;
pub(super) const SUBSCRIPTION_ID: &str = "nip46-persistent";
pub(super) const CONNECT_PERMS: &str = "sign_event,get_public_key,nip44_encrypt,nip44_decrypt";
/// A genuine response is at most about 88 KB of NIP-44 base64 plus its envelope.
pub(super) const MAX_FRAME_CHARS: usize = 262_144;
const MAX_AUTH_URL_BYTES: usize = 2048;

const MALFORMED_RESPONSE: &str = "remote signer sent a malformed response";
const MISSING_RESULT: &str = "remote signer sent a response with no result";
const UNEXPECTED_RESULT: &str = "remote signer sent an unexpected result";
/// Fixed text for a refused `auth_url`. It must never quote the URL.
const REFUSED_AUTH_URL: &str = "remote signer sent an approval link that is not a safe https URL";
const REQUEST_BUILD_FAILED: &str = "could not build the request";
/// Fixed text for a socket that went away. A close carries nothing trusted.
const SOCKET_LOST: &str = "relay connection lost";
const SOCKET_REPLACED: &str = "relay connection replaced while this request was pending; the signer may still have received it, so check before retrying";
pub(super) const RECONNECT_CANCELLED: &str = "reconnect cancelled";

pub(super) struct BunkerTarget {
    pub(super) remote: PublicKey,
    /// In order, without duplicates.
    pub(super) relays: Vec<RelayUrl>,
    /// One-time pairing secret. Never persisted.
    pub(super) secret: Option<String>,
}

/// Error texts are fixed, so they cannot quote the secret.
pub(super) fn parse_bunker_uri(uri: &str) -> Result<BunkerTarget, NostrAuthError> {
    if uri.starts_with("nostrconnect://") {
        return Err(NostrAuthError::InvalidBunkerUri(
            "nostrconnect:// (client-initiated pairing) is not yet supported — \
             paste the bunker:// URI shown by your remote signer instead"
                .into(),
        ));
    }
    if !uri.starts_with("bunker://") {
        return Err(NostrAuthError::InvalidBunkerUri(
            "URI must start with bunker://".into(),
        ));
    }
    let Ok(NostrConnectUri::Bunker {
        remote_signer_public_key: remote,
        relays: listed,
        secret,
    }) = NostrConnectUri::parse(uri)
    else {
        return Err(NostrAuthError::InvalidBunkerUri("invalid URI".into()));
    };
    // Upstream's URI parser uses `from_hex`, which accepts a key off the curve.
    if super::check_on_curve(&remote).is_err() {
        return Err(NostrAuthError::InvalidBunkerUri("invalid URI".into()));
    }
    let mut relays: Vec<RelayUrl> = Vec::with_capacity(listed.len());
    for relay in listed {
        if !relays.contains(&relay) {
            relays.push(relay);
        }
    }
    if relays.is_empty() {
        return Err(NostrAuthError::InvalidBunkerUri("missing relay URL".into()));
    }
    if relays
        .iter()
        .any(|r| r.scheme() == RelayUrlScheme::Ws && !r.is_localhost())
    {
        return Err(NostrAuthError::InvalidBunkerUri(
            "relay must use wss://".into(),
        ));
    }
    if relays.len() > MAX_BUNKER_RELAYS {
        return Err(NostrAuthError::InvalidBunkerUri(format!(
            "too many relays, the limit is {MAX_BUNKER_RELAYS}"
        )));
    }
    Ok(BunkerTarget {
        remote,
        relays,
        secret,
    })
}

/// The URI to persist: every relay, no secret.
pub(super) fn persisted_uri(
    remote: &PublicKey,
    relays: &[RelayUrl],
) -> Result<String, NostrAuthError> {
    let Ok(mut uri) = Url::parse(&format!("bunker://{}", remote.to_hex())) else {
        return Err(NostrAuthError::InvalidBunkerUri("invalid URI".into()));
    };
    {
        let mut query = uri.query_pairs_mut();
        for relay in relays {
            // A parsed `Url` would serialise `wss://relay.example` with a trailing slash.
            query.append_pair("relay", relay.as_str());
        }
    }
    Ok(uri.into())
}

/// So the next restore tries the working relay first.
pub(super) fn rotate_to_front(relays: &mut Vec<RelayUrl>, working: &RelayUrl) {
    if let Some(position) = relays.iter().position(|relay| relay == working) {
        let relay = relays.remove(position);
        relays.insert(0, relay);
    }
}

pub(super) enum Handshake {
    Pair {
        secret: Option<String>,
    },
    /// Restore a client the signer already knows. Any secret in the stored URI is ignored.
    Restore,
}

/// Whether `connect` still has to be sent. A verified ack spends the secret, and NIP-46 makes a
/// secret good for one connection, so later relays must not repeat it.
pub(super) const fn needs_connect(handshake: &Handshake, paired: bool) -> bool {
    matches!(handshake, Handshake::Pair { .. }) && !paired
}

pub(super) fn connect_request(handshake: &Handshake, remote: PublicKey) -> NostrConnectRequest {
    NostrConnectRequest::Connect {
        remote_signer_public_key: remote,
        secret: match handshake {
            Handshake::Pair { secret } => secret.clone(),
            Handshake::Restore => None,
        },
    }
}

/// Build a request with our own id. Upstream's `request()` uses 32-bit ids, and its `Connect`
/// params drop the requested permissions.
pub(super) fn request_message(id: String, request: &NostrConnectRequest) -> NostrConnectMessage {
    let params = match request {
        NostrConnectRequest::Connect {
            remote_signer_public_key,
            secret,
        } => vec![
            remote_signer_public_key.to_hex(),
            secret.clone().unwrap_or_default(),
            CONNECT_PERMS.to_owned(),
        ],
        other => other.params(),
    };
    NostrConnectMessage::Request {
        id,
        method: request.method(),
        params,
    }
}

/// Encrypt and sign a kind 24133 event. Takes the time as an argument because upstream's builder
/// reads the system clock, which this crate must not reach on wasm.
pub(super) fn request_event(
    keys: &Keys,
    remote: PublicKey,
    message: &NostrConnectMessage,
    created_at: Timestamp,
) -> Option<Event> {
    let content = nip44::encrypt(
        keys.secret_key(),
        &remote,
        message.as_json(),
        nip44::Version::V2,
    )
    .ok()?;
    UnsignedEvent::new(
        keys.public_key(),
        created_at,
        Kind::NostrConnect,
        [Tag::public_key(remote)],
        content,
    )
    .finalize(keys)
    .ok()
}

pub(super) fn subscribe_frame(client: PublicKey) -> String {
    ClientMessage::req(
        SubscriptionId::new(SUBSCRIPTION_ID),
        vec![Filter::new().kind(Kind::NostrConnect).pubkey(client)],
    )
    .as_json()
}

pub(super) fn event_frame(event: &Event) -> String {
    ClientMessage::event(event.clone()).as_json()
}

/// An approval link that passed every check. Only `parse_auth_url` builds one, and it has no
/// `Debug`, because these URLs carry tokens.
pub(super) struct HttpsUrl(String);

impl HttpsUrl {
    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Approval links on show, oldest first, keyed by request id. The newest is the one displayed, so
/// removing it exposes the previous one.
#[derive(Default)]
pub(super) struct PromptList(Vec<(String, HttpsUrl)>);

impl PromptList {
    pub(super) fn upsert(&mut self, id: String, url: HttpsUrl) {
        self.remove(&id);
        self.0.push((id, url));
    }

    pub(super) fn has(&self, id: &str) -> bool {
        self.0.iter().any(|(owner, _)| owner == id)
    }

    pub(super) fn remove(&mut self, id: &str) -> bool {
        let before = self.0.len();
        self.0.retain(|(owner, _)| owner != id);
        self.0.len() != before
    }

    pub(super) fn remove_current(&mut self) {
        self.0.pop();
    }

    pub(super) fn current(&self) -> Option<&str> {
        self.0.last().map(|(_, url)| url.as_str())
    }
}

pub(super) fn auth_url_host(url: &str) -> Option<String> {
    Url::parse(url).ok()?.host_str().map(str::to_owned)
}

/// Accept a link only if it is https with a host and no credentials. The stored form is the parsed
/// one, never the raw string.
pub(super) fn parse_auth_url(raw: &str) -> Option<HttpsUrl> {
    if raw.len() > MAX_AUTH_URL_BYTES {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none_or(str::is_empty)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let parsed: String = url.into();
    (parsed.len() <= MAX_AUTH_URL_BYTES).then_some(HttpsUrl(parsed))
}

pub(super) enum RpcFailure {
    Timeout {
        /// A verified signer had already answered this request.
        signer_answered: bool,
        /// The relay on this socket sent a NIP-42 challenge.
        relay_asked_auth: bool,
    },
    /// A verified signer asked for approval, and no modal can show the link.
    AuthRequired,
    /// The socket failed before the request was sent.
    Socket(NostrAuthError),
    /// The socket went away after the request was sent.
    SocketLost {
        signer_answered: bool,
        /// The crate closed a socket that was still open, so the signer may still receive the
        /// request.
        replaced: bool,
    },
    /// The relay refused. Relay frames are unauthenticated, so this may be a hostile relay.
    Relay {
        /// Sanitised relay text.
        reason: String,
        signer_answered: bool,
    },
    /// A verified signer refused, with its sanitised text.
    Signer(String),
    /// A verified response was unusable. Fixed text only: parser errors can quote values.
    Malformed(&'static str),
    /// The request could not be built locally, which proves nothing about the socket.
    Build,
    SessionClosed,
}

impl fmt::Debug for RpcFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout {
                signer_answered,
                relay_asked_auth,
            } => f
                .debug_struct("Timeout")
                .field("signer_answered", signer_answered)
                .field("relay_asked_auth", relay_asked_auth)
                .finish(),
            Self::AuthRequired => f.write_str("AuthRequired"),
            Self::Socket(e) => f.debug_tuple("Socket").field(e).finish(),
            Self::SocketLost {
                signer_answered,
                replaced,
            } => f
                .debug_struct("SocketLost")
                .field("signer_answered", signer_answered)
                .field("replaced", replaced)
                .finish(),
            Self::Relay {
                reason,
                signer_answered,
            } => f
                .debug_struct("Relay")
                .field("reason", reason)
                .field("signer_answered", signer_answered)
                .finish(),
            Self::Signer(text) => f.debug_tuple("Signer").field(text).finish(),
            Self::Malformed(text) => f.debug_tuple("Malformed").field(text).finish(),
            Self::Build => f.write_str("Build"),
            Self::SessionClosed => f.write_str("SessionClosed"),
        }
    }
}

impl RpcFailure {
    /// Whether the next relay may be tried. Once a verified signer has answered, another relay
    /// only repeats the question, and a relay must not be able to restart an auth wait.
    pub(super) const fn advances_to_next_relay(&self) -> bool {
        matches!(
            self,
            Self::Timeout {
                signer_answered: false,
                ..
            } | Self::Socket(_)
                | Self::SocketLost {
                    signer_answered: false,
                    ..
                }
                | Self::Relay {
                    signer_answered: false,
                    ..
                }
        )
    }

    pub(super) fn into_connect_error(self) -> NostrAuthError {
        match self {
            Self::Malformed(text) => NostrAuthError::BunkerConnectionFailed(text.to_owned()),
            Self::Build => NostrAuthError::BunkerConnectionFailed(REQUEST_BUILD_FAILED.to_owned()),
            other => other.into_shared_error(),
        }
    }

    pub(super) fn into_signing_error(self) -> NostrAuthError {
        match self {
            Self::Malformed(text) => NostrAuthError::SigningFailed(text.to_owned()),
            Self::Build => NostrAuthError::SigningFailed(REQUEST_BUILD_FAILED.to_owned()),
            Self::Signer(text) => NostrAuthError::SigningFailed(text),
            other => other.into_shared_error(),
        }
    }

    pub(super) fn into_encryption_error(self) -> NostrAuthError {
        match self {
            Self::Malformed(text) => NostrAuthError::EncryptionFailed(text.to_owned()),
            Self::Build => NostrAuthError::EncryptionFailed(REQUEST_BUILD_FAILED.to_owned()),
            Self::Signer(text) => NostrAuthError::EncryptionFailed(text),
            other => other.into_shared_error(),
        }
    }

    fn into_shared_error(self) -> NostrAuthError {
        match self {
            Self::Timeout {
                signer_answered: false,
                relay_asked_auth: true,
            } => NostrAuthError::BunkerConnectionFailed(
                "the remote signer did not answer; the relay also asked for NIP-42 authentication, \
                 which this client does not support"
                    .into(),
            ),
            Self::Timeout { .. } => NostrAuthError::BunkerTimeout,
            Self::AuthRequired => NostrAuthError::BunkerAuthRequired,
            Self::Socket(e) => e,
            Self::SocketLost { replaced: true, .. } => {
                NostrAuthError::BunkerConnectionFailed(SOCKET_REPLACED.into())
            }
            Self::SocketLost { .. } => NostrAuthError::BunkerConnectionFailed(SOCKET_LOST.into()),
            Self::Relay { reason, .. } if reason.starts_with("auth-required:") => {
                NostrAuthError::BunkerConnectionFailed(
                    "the relay requires NIP-42 authentication, which this client does not support"
                        .into(),
                )
            }
            Self::Relay { reason, .. } => {
                NostrAuthError::BunkerConnectionFailed(format!("relay refused: {reason}"))
            }
            Self::Signer(text) => NostrAuthError::BunkerConnectionFailed(text),
            Self::Malformed(text) => NostrAuthError::BunkerConnectionFailed(text.to_owned()),
            Self::Build => NostrAuthError::BunkerConnectionFailed(REQUEST_BUILD_FAILED.to_owned()),
            Self::SessionClosed => NostrAuthError::BunkerSessionClosed,
        }
    }
}

#[derive(Default)]
pub(super) struct AttemptLog {
    relay_reason: Option<RpcFailure>,
    last: Option<RpcFailure>,
}

impl AttemptLog {
    /// Returns the failure if it ends the handshake now, so no earlier relay's reason can replace
    /// it.
    pub(super) fn record(&mut self, failure: RpcFailure) -> Option<RpcFailure> {
        if !failure.advances_to_next_relay() {
            return Some(failure);
        }
        if matches!(failure, RpcFailure::Relay { .. }) {
            self.relay_reason = Some(failure);
        } else {
            self.last = Some(failure);
        }
        None
    }

    pub(super) fn finish(self) -> RpcFailure {
        self.relay_reason.or(self.last).unwrap_or_else(|| {
            RpcFailure::Socket(NostrAuthError::BunkerConnectionFailed(
                "no relay to try".into(),
            ))
        })
    }
}

/// `connect` either succeeded or failed: returning `()` means it cannot carry an identity. The
/// echoed value is discarded, because it may be the secret. Any reply but `ack` or the echoed
/// secret is the signer's refusal.
pub(super) fn connect_result(
    result: ResponseResult,
    secret: Option<&str>,
) -> Result<(), RpcFailure> {
    let secret = secret.filter(|s| !s.is_empty());
    match result {
        ResponseResult::Ack => Ok(()),
        ResponseResult::ConnectSecret(echo) if secret == Some(echo.as_str()) => Ok(()),
        ResponseResult::ConnectSecret(text) => {
            let shown = sanitize_remote_text(&text);
            let quotes_secret = secret.is_some_and(|s| {
                let s = sanitize_remote_text(s);
                !s.is_empty() && shown.contains(&s)
            });
            if shown.is_empty() || quotes_secret {
                Err(RpcFailure::Malformed(UNEXPECTED_RESULT))
            } else {
                Err(RpcFailure::Signer(shown))
            }
        }
        _ => Err(RpcFailure::Malformed(UNEXPECTED_RESULT)),
    }
}

/// The only source of the session's identity. `from_hex` does not check the curve.
pub(super) fn public_key_result(result: ResponseResult) -> Result<PublicKey, RpcFailure> {
    result
        .to_get_public_key()
        .ok()
        .filter(|key| key.xonly().is_ok())
        .ok_or(RpcFailure::Malformed(UNEXPECTED_RESULT))
}

/// The signed event, shape-checked only.
pub(super) fn signed_event_result(result: ResponseResult) -> Result<String, RpcFailure> {
    match result {
        ResponseResult::SignEvent(event) => Ok(event.as_json()),
        _ => Err(RpcFailure::Malformed(UNEXPECTED_RESULT)),
    }
}

pub(super) fn nip44_result(result: ResponseResult) -> Result<String, RpcFailure> {
    match result {
        ResponseResult::Nip44Encrypt { ciphertext } if is_nip44_payload(&ciphertext) => {
            Ok(ciphertext)
        }
        ResponseResult::Nip44Decrypt { plaintext } => Ok(plaintext),
        _ => Err(RpcFailure::Malformed(UNEXPECTED_RESULT)),
    }
}

/// What `result` means for a method. Upstream's `ResponseResult::parse` reads the literals `error`
/// and `auth_url` as control values, which would misread a decrypted plaintext, so NIP-44 bypasses it.
fn typed_result(method: NostrConnectMethod, result: String) -> Result<ResponseResult, RpcFailure> {
    match method {
        NostrConnectMethod::Nip44Encrypt => Ok(ResponseResult::Nip44Encrypt { ciphertext: result }),
        NostrConnectMethod::Nip44Decrypt => Ok(ResponseResult::Nip44Decrypt { plaintext: result }),
        _ => ResponseResult::parse(method, result)
            .ok()
            .ok_or(RpcFailure::Malformed(UNEXPECTED_RESULT)),
    }
}

#[derive(Clone)]
pub(super) struct Peer {
    pub(super) client: Keys,
    /// The configured remote signer. Never taken from a frame.
    pub(super) remote: PublicKey,
}

/// What a relay frame caused. Handlers run these after the `Inflight` borrow has ended.
pub(super) enum Effect<W> {
    Settle {
        waker: W,
        outcome: Result<ResponseResult, RpcFailure>,
    },
    /// The request stays pending.
    Prompt { request_id: String, url: HttpsUrl },
    /// Close the socket, so the next call resubscribes.
    CloseSocket,
}

/// How a reconnect ended. Passed by value, so no error text has to survive a trip through JS.
pub(super) type ReconnectOutcome = Result<(), NostrAuthError>;

pub(super) trait ReconnectWaker {
    fn wake(self, outcome: ReconnectOutcome);
}

/// Serializes reconnects: the first caller leads, and the rest wait for its outcome.
pub(super) struct ReconnectGate<W> {
    /// `None` when no reconnect is running.
    followers: RefCell<Option<Vec<W>>>,
}

impl<W> Default for ReconnectGate<W> {
    fn default() -> Self {
        Self {
            followers: RefCell::new(None),
        }
    }
}

impl<W: ReconnectWaker> ReconnectGate<W> {
    /// Lead on an idle gate, dropping `waker`. Otherwise register `waker` and return `None`.
    pub(super) fn join(self: &Rc<Self>, waker: W) -> Option<ReconnectLead<W>> {
        let mut followers = self.followers.borrow_mut();
        if let Some(waiting) = followers.as_mut() {
            waiting.push(waker);
            return None;
        }
        *followers = Some(Vec::new());
        Some(ReconnectLead {
            gate: Rc::clone(self),
            outcome: None,
        })
    }
}

/// The running reconnect. Dropping it reopens the gate and wakes the followers, including when the
/// leader's future is dropped, which runs no exit code.
pub(super) struct ReconnectLead<W: ReconnectWaker> {
    gate: Rc<ReconnectGate<W>>,
    outcome: Option<ReconnectOutcome>,
}

impl<W: ReconnectWaker> ReconnectLead<W> {
    pub(super) fn finish(mut self, outcome: ReconnectOutcome) {
        self.outcome = Some(outcome);
    }
}

impl<W: ReconnectWaker> Drop for ReconnectLead<W> {
    fn drop(&mut self) {
        let followers = self.gate.followers.borrow_mut().take().unwrap_or_default();
        let outcome = self.outcome.take().unwrap_or_else(|| {
            Err(NostrAuthError::BunkerConnectionFailed(
                RECONNECT_CANCELLED.to_owned(),
            ))
        });
        for follower in followers {
            follower.wake(outcome.clone());
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) enum DeadlineAction {
    Extend,
    Timeout { signer_answered: bool },
    AuthRequired,
}

struct Pending<W> {
    /// Decides how `result` is read.
    method: NostrConnectMethod,
    /// Matches `OK` frames to this request.
    event_id: EventId,
    waker: W,
    /// A verified signer sent a valid `auth_url` for this request.
    auth_seen: bool,
    /// The one extension has been used.
    extended: bool,
}

/// The `{ id }` of a response that does not otherwise parse.
#[derive(Deserialize)]
struct ResponseId {
    id: String,
}

/// In-flight requests, and the only entry point for relay bytes. Every field in a relay frame is
/// hostile. Generic over the waker so native tests can drive it with no browser.
pub(super) struct Inflight<W> {
    entries: HashMap<String, Pending<W>>,
    /// The relay on the current socket sent a NIP-42 challenge.
    auth_requested: bool,
    /// A request timed out on the current socket while others were still pending.
    suspect: bool,
}

impl<W> Default for Inflight<W> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            auth_requested: false,
            suspect: false,
        }
    }
}

impl<W> Inflight<W> {
    pub(super) fn insert(
        &mut self,
        id: String,
        method: NostrConnectMethod,
        event_id: EventId,
        waker: W,
    ) {
        self.entries.insert(
            id,
            Pending {
                method,
                event_id,
                waker,
                auth_seen: false,
                extended: false,
            },
        );
    }

    pub(super) fn remove(&mut self, id: &str) {
        self.entries.remove(id);
    }

    #[cfg(test)]
    pub(super) fn contains(&self, id: &str) -> bool {
        self.entries.contains_key(id)
    }

    /// Clear per-socket state on each new socket, so one relay's challenge does not name NIP-42
    /// on a later relay's timeout.
    pub(super) const fn reset_socket(&mut self) {
        self.auth_requested = false;
        self.suspect = false;
    }

    /// Record how a request on the current socket ended, `None` meaning success. Call after its
    /// entry is gone. Returns whether to tear the socket down now. A failure that only a live
    /// signer on this socket can produce proves the socket alive.
    pub(super) fn note_settled(&mut self, failure: Option<&RpcFailure>) -> bool {
        match failure {
            None
            | Some(
                RpcFailure::Signer(_)
                | RpcFailure::AuthRequired
                | RpcFailure::Malformed(_)
                | RpcFailure::Timeout {
                    signer_answered: true,
                    ..
                },
            ) => {
                self.suspect = false;
                false
            }
            Some(RpcFailure::Timeout {
                signer_answered: false,
                ..
            }) => {
                if self.entries.is_empty() {
                    return true;
                }
                self.suspect = true;
                false
            }
            Some(_) => false,
        }
    }

    /// Whether a new request must reconnect rather than use the current socket. A verified
    /// approval wait keeps it, because reconnecting would end that wait.
    pub(super) fn must_reconnect(&self) -> bool {
        self.suspect && !self.entries.values().any(|entry| entry.auth_seen)
    }

    /// A dropped frame yields no effects and the request stays pending.
    pub(super) fn on_frame(&mut self, data: &str, peer: &Peer) -> Vec<Effect<W>> {
        if data.len() > MAX_FRAME_CHARS {
            return Vec::new();
        }
        let Ok(message) = RelayMessage::from_json(data) else {
            return Vec::new();
        };
        match message {
            RelayMessage::Event {
                subscription_id,
                event,
            } if subscription_id.as_str() == SUBSCRIPTION_ID => self.on_event(&event, peer),
            RelayMessage::Ok {
                event_id,
                status: false,
                message,
            } => self.on_rejected(event_id, &message),
            RelayMessage::Closed {
                subscription_id,
                message,
            } if subscription_id.as_str() == SUBSCRIPTION_ID => {
                let mut effects = self.fail_all(&message);
                effects.push(Effect::CloseSocket);
                effects
            }
            RelayMessage::Auth { .. } => {
                self.auth_requested = true;
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// A response event. Nothing past `verify` runs for an unverified frame, so no link, identity
    /// or result can come from one.
    fn on_event(&mut self, event: &Event, peer: &Peer) -> Vec<Effect<W>> {
        if event.kind != Kind::NostrConnect {
            return Vec::new();
        }
        if event.pubkey != peer.remote {
            return Vec::new();
        }
        if !event
            .tags
            .public_keys()
            .any(|key| key == peer.client.public_key())
        {
            return Vec::new();
        }
        if event.verify().is_err() {
            return Vec::new();
        }
        let Ok(plaintext) = nip44::decrypt(
            peer.client.secret_key(),
            &peer.remote,
            event.content.as_str(),
        ) else {
            return Vec::new();
        };
        // NIP-44 keys are symmetric, so a reflected request decrypts: only its shape rejects it.
        match NostrConnectMessage::from_json(&plaintext) {
            Ok(NostrConnectMessage::Request { .. }) => Vec::new(),
            Ok(NostrConnectMessage::Response { id, result, error }) => {
                self.on_response(&id, result, error)
            }
            // A non-string `result` fails the whole parse. A known id still gets a prompt error.
            Err(_) => serde_json::from_str::<ResponseId>(&plaintext).map_or_else(
                |_| Vec::new(),
                |ResponseId { id }| {
                    self.settle(&id, Err(RpcFailure::Malformed(MALFORMED_RESPONSE)))
                },
            ),
        }
    }

    fn on_response(
        &mut self,
        id: &str,
        result: Option<String>,
        error: Option<String>,
    ) -> Vec<Effect<W>> {
        let Some(entry) = self.entries.get_mut(id) else {
            return Vec::new();
        };
        let method = entry.method;
        let error = error.filter(|text| !text.is_empty());
        if let (Some("auth_url"), Some(url)) = (result.as_deref(), error.as_deref()) {
            let Some(url) = parse_auth_url(url) else {
                return self.settle(id, Err(RpcFailure::Malformed(REFUSED_AUTH_URL)));
            };
            entry.auth_seen = true;
            return vec![Effect::Prompt {
                request_id: id.to_owned(),
                url,
            }];
        }
        if let Some(text) = error {
            return self.settle(id, Err(RpcFailure::Signer(sanitize_remote_text(&text))));
        }
        let outcome = result.map_or(Err(RpcFailure::Malformed(MISSING_RESULT)), |result| {
            typed_result(method, result)
        });
        self.settle(id, outcome)
    }

    fn on_rejected(&mut self, event_id: EventId, message: &str) -> Vec<Effect<W>> {
        let Some(id) = self
            .entries
            .iter()
            .find(|(_, entry)| entry.event_id == event_id)
            .map(|(id, _)| id.clone())
        else {
            return Vec::new();
        };
        let signer_answered = self.entries.get(&id).is_some_and(|entry| entry.auth_seen);
        self.settle(
            &id,
            Err(RpcFailure::Relay {
                reason: sanitize_remote_text(message),
                signer_answered,
            }),
        )
    }

    /// Removing the entry makes a replayed response inert.
    fn settle(&mut self, id: &str, outcome: Result<ResponseResult, RpcFailure>) -> Vec<Effect<W>> {
        self.entries.remove(id).map_or_else(Vec::new, |entry| {
            vec![Effect::Settle {
                waker: entry.waker,
                outcome,
            }]
        })
    }

    /// Each takes `signer_answered` from its own entry.
    pub(super) fn fail_all(&mut self, reason: &str) -> Vec<Effect<W>> {
        let reason = sanitize_remote_text(reason);
        self.fail_all_with(|signer_answered| RpcFailure::Relay {
            reason: reason.clone(),
            signer_answered,
        })
    }

    pub(super) fn fail_socket_lost(&mut self) -> Vec<Effect<W>> {
        self.fail_all_with(|signer_answered| RpcFailure::SocketLost {
            signer_answered,
            replaced: false,
        })
    }

    pub(super) fn fail_socket_replaced(&mut self) -> Vec<Effect<W>> {
        self.fail_all_with(|signer_answered| RpcFailure::SocketLost {
            signer_answered,
            replaced: true,
        })
    }

    pub(super) fn fail_session_closed(&mut self) -> Vec<Effect<W>> {
        self.fail_all_with(|_| RpcFailure::SessionClosed)
    }

    fn fail_all_with(&mut self, failure: impl Fn(bool) -> RpcFailure) -> Vec<Effect<W>> {
        self.entries
            .drain()
            .map(|(_, entry)| Effect::Settle {
                waker: entry.waker,
                outcome: Err(failure(entry.auth_seen)),
            })
            .collect()
    }

    /// Decide what a fired timer means. `presenter_mounted` is read at the timer rather than when
    /// `auth_url` arrives, which covers a modal mounting during the wait.
    pub(super) fn on_deadline(&mut self, id: &str, presenter_mounted: bool) -> DeadlineAction {
        let Some(entry) = self.entries.get_mut(id) else {
            return DeadlineAction::Timeout {
                signer_answered: false,
            };
        };
        if !entry.auth_seen {
            return DeadlineAction::Timeout {
                signer_answered: false,
            };
        }
        if !presenter_mounted {
            return DeadlineAction::AuthRequired;
        }
        if entry.extended {
            return DeadlineAction::Timeout {
                signer_answered: true,
            };
        }
        entry.extended = true;
        DeadlineAction::Extend
    }

    pub(super) const fn timeout_failure(&self, signer_answered: bool) -> RpcFailure {
        RpcFailure::Timeout {
            signer_answered,
            relay_asked_auth: self.auth_requested,
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod tests {
    use super::*;
    use crate::signers::MAX_REMOTE_TEXT_CHARS;
    use crate::signers::event_contract::prepare;
    use nostr::event::Tags;

    const ID: &str = "req-1";
    const AT: u64 = 1_700_000_000;

    struct Fx {
        client: Keys,
        remote: Keys,
        inflight: Inflight<()>,
    }

    impl Fx {
        fn new(method: NostrConnectMethod) -> Self {
            let mut inflight = Inflight::default();
            inflight.insert(ID.to_owned(), method, other_event_id(), ());
            Self {
                client: Keys::generate(),
                remote: Keys::generate(),
                inflight,
            }
        }

        fn peer(&self) -> Peer {
            Peer {
                client: self.client.clone(),
                remote: self.remote.public_key(),
            }
        }

        fn feed(&mut self, frame: &str) -> Vec<Effect<()>> {
            let peer = self.peer();
            self.inflight.on_frame(frame, &peer)
        }

        fn signed(&self, plaintext: &str) -> Event {
            signed_by(
                &self.remote,
                self.client.public_key(),
                &self.remote,
                self.client.public_key(),
                plaintext,
            )
        }

        fn response(&self, result: &str) -> Event {
            self.signed(&format!(r#"{{"id":"{ID}","result":"{result}"}}"#))
        }

        fn pending(&self) -> bool {
            self.inflight.entries.contains_key(ID)
        }

        fn auth_seen(&self) -> bool {
            self.inflight.entries.get(ID).unwrap().auth_seen
        }

        fn prompt_from_genuine_auth_url(mut self) -> Vec<Effect<()>> {
            let challenge = auth_url_event(&self, TOKEN_URL);
            self.feed(&frame(&challenge))
        }
    }

    fn other_event_id() -> EventId {
        EventId::from_byte_array([7; 32])
    }

    fn signed_by(
        signer: &Keys,
        tagged: PublicKey,
        encrypt_with: &Keys,
        encrypt_to: PublicKey,
        plaintext: &str,
    ) -> Event {
        let content = nip44::encrypt(
            encrypt_with.secret_key(),
            &encrypt_to,
            plaintext,
            nip44::Version::V2,
        )
        .unwrap();
        UnsignedEvent::new(
            signer.public_key(),
            Timestamp::from_secs(AT),
            Kind::NostrConnect,
            [Tag::public_key(tagged)],
            content,
        )
        .finalize(signer)
        .unwrap()
    }

    fn frame(event: &Event) -> String {
        RelayMessage::event(SubscriptionId::new(SUBSCRIPTION_ID), event.clone()).as_json()
    }

    fn value_frame(event: &serde_json::Value) -> String {
        serde_json::json!(["EVENT", SUBSCRIPTION_ID, event]).to_string()
    }

    fn set(value: &mut serde_json::Value, field: &str, to: serde_json::Value) {
        *value.get_mut(field).unwrap() = to;
    }

    fn recomputed_id(value: &serde_json::Value) -> String {
        let event: Event = serde_json::from_value(value.clone()).unwrap();
        let tags: Tags = event.tags.clone();
        EventId::compute(
            &event.pubkey,
            &event.created_at,
            &event.kind,
            &tags,
            &event.content,
        )
        .to_hex()
    }

    fn only_outcome(mut effects: Vec<Effect<()>>) -> Result<ResponseResult, RpcFailure> {
        assert_eq!(effects.len(), 1);
        match effects.pop().unwrap() {
            Effect::Settle { outcome, .. } => outcome,
            _ => unreachable!("expected a settle"),
        }
    }

    fn assert_positive_control(method: NostrConnectMethod, make: impl Fn(&Fx) -> Event) {
        let mut fx = Fx::new(method);
        let event = make(&fx);
        assert!(only_outcome(fx.feed(&frame(&event))).is_ok());
        assert!(!fx.pending());
    }

    fn assert_dropped(fx: &mut Fx, frame: &str) {
        assert!(fx.feed(frame).is_empty());
        assert!(fx.pending());
    }

    #[test]
    fn nip46_event_shape() {
        let client = Keys::generate();
        let remote = Keys::generate().public_key();
        let at = Timestamp::from_secs(AT);
        let message = request_message("1".into(), &NostrConnectRequest::GetPublicKey);
        let ev = request_event(&client, remote, &message, at).unwrap();
        assert_eq!(ev.kind, Kind::NostrConnect);
        assert_eq!(ev.kind.as_u16(), 24133);
        assert_eq!(ev.pubkey, client.public_key());
        assert_eq!(ev.created_at, at);
        let tags: Vec<_> = ev.tags.iter().collect();
        assert_eq!(tags.len(), 1);
        assert_eq!(
            tags.first().unwrap().as_slice(),
            ["p".to_owned(), remote.to_hex()]
        );
        ev.verify().unwrap();
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn wasm_nip46_event_signs_with_js_date_clock() {
        let client = Keys::generate();
        let remote = Keys::generate().public_key();
        let message = request_message("1".into(), &NostrConnectRequest::GetPublicKey);
        let ev = request_event(
            &client,
            remote,
            &message,
            crate::signers::browser::now_timestamp(),
        )
        .unwrap();
        ev.verify().unwrap();
        assert!(ev.created_at.as_secs() > AT);
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn wasm_genuine_frame_settles_and_wrong_signature_does_not() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let other = fx.response("other");
        let mut forged = serde_json::to_value(fx.response("ack")).unwrap();
        set(&mut forged, "sig", serde_json::to_value(other.sig).unwrap());
        assert_dropped(&mut fx, &value_frame(&forged));
        let genuine = fx.response("ack");
        assert!(only_outcome(fx.feed(&frame(&genuine))).is_ok());
    }

    // Verification: each starts from a genuine frame and changes one thing.

    #[test]
    fn rejects_valid_response_with_wrong_signature() {
        assert_positive_control(NostrConnectMethod::Connect, |fx| fx.response("ack"));
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let other = fx.response("other");
        let mut forged = serde_json::to_value(fx.response("ack")).unwrap();
        set(&mut forged, "sig", serde_json::to_value(other.sig).unwrap());
        assert_dropped(&mut fx, &value_frame(&forged));
    }

    #[test]
    fn rejects_valid_response_with_altered_field() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let mut altered = serde_json::to_value(fx.response("ack")).unwrap();
        set(&mut altered, "created_at", (AT + 1).into());
        assert_dropped(&mut fx, &value_frame(&altered));
    }

    #[test]
    fn rejects_response_signed_by_attacker_claiming_signer() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let attacker = Keys::generate();
        let mut forged = serde_json::to_value(fx.response("ack")).unwrap();
        set(
            &mut forged,
            "pubkey",
            fx.remote.public_key().to_hex().into(),
        );
        let id = recomputed_id(&forged);
        let sig = attacker.sign_schnorr(EventId::from_hex(&id).unwrap().as_bytes());
        set(&mut forged, "id", id.into());
        set(&mut forged, "sig", serde_json::to_value(sig).unwrap());
        assert_dropped(&mut fx, &value_frame(&forged));
    }

    #[test]
    fn rejects_wrong_signature_on_get_public_key() {
        let different = Keys::generate().public_key().to_hex();
        assert_positive_control(NostrConnectMethod::GetPublicKey, |fx| {
            fx.response(&different)
        });
        let mut fx = Fx::new(NostrConnectMethod::GetPublicKey);
        let other = fx.response("other");
        let mut forged = serde_json::to_value(fx.response(&different)).unwrap();
        set(&mut forged, "sig", serde_json::to_value(other.sig).unwrap());
        assert_dropped(&mut fx, &value_frame(&forged));
    }

    fn reflected(fx: &Fx) -> serde_json::Value {
        let message = request_message(ID.to_owned(), &NostrConnectRequest::GetPublicKey);
        let request = request_event(
            &fx.client,
            fx.remote.public_key(),
            &message,
            Timestamp::from_secs(AT),
        )
        .unwrap();
        let mut value = serde_json::to_value(request).unwrap();
        set(&mut value, "pubkey", fx.remote.public_key().to_hex().into());
        value
    }

    #[test]
    fn rejects_reflected_request() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let value = reflected(&fx);
        assert_dropped(&mut fx, &value_frame(&value));
    }

    #[test]
    fn rejects_reflected_request_with_rewritten_tag() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let mut value = reflected(&fx);
        let client = fx.client.public_key().to_hex();
        set(&mut value, "tags", serde_json::json!([["p", client]]));
        let id = recomputed_id(&value);
        set(&mut value, "id", id.into());
        assert_dropped(&mut fx, &value_frame(&value));
    }

    #[test]
    fn rejects_request_shape_from_real_signer() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let plaintext = request_message(ID.to_owned(), &NostrConnectRequest::GetPublicKey);
        let event = fx.signed(&plaintext.as_json());
        assert_dropped(&mut fx, &frame(&event));
    }

    #[test]
    fn rejects_wrong_author() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let attacker = Keys::generate();
        // Replayed signer ciphertext, so only the author check can stop it.
        let event = signed_by(
            &attacker,
            fx.client.public_key(),
            &fx.remote,
            fx.client.public_key(),
            &format!(r#"{{"id":"{ID}","result":"ack"}}"#),
        );
        assert_dropped(&mut fx, &frame(&event));
    }

    #[test]
    fn rejects_missing_or_foreign_p_tag() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let plaintext = format!(r#"{{"id":"{ID}","result":"ack"}}"#);
        let foreign = signed_by(
            &fx.remote,
            Keys::generate().public_key(),
            &fx.remote,
            fx.client.public_key(),
            &plaintext,
        );
        assert_dropped(&mut fx, &frame(&foreign));
        let content = nip44::encrypt(
            fx.remote.secret_key(),
            &fx.client.public_key(),
            &plaintext,
            nip44::Version::V2,
        )
        .unwrap();
        let untagged = UnsignedEvent::new(
            fx.remote.public_key(),
            Timestamp::from_secs(AT),
            Kind::NostrConnect,
            [],
            content,
        )
        .finalize(&fx.remote)
        .unwrap();
        assert_dropped(&mut fx, &frame(&untagged));
    }

    #[test]
    fn rejects_wrong_kind() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let genuine = fx.response("ack");
        let event = UnsignedEvent::new(
            genuine.pubkey,
            genuine.created_at,
            Kind::TextNote,
            [Tag::public_key(fx.client.public_key())],
            genuine.content,
        )
        .finalize(&fx.remote)
        .unwrap();
        assert_dropped(&mut fx, &frame(&event));
    }

    #[test]
    fn rejects_wrong_subscription() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let event = fx.response("ack");
        let foreign = RelayMessage::event(SubscriptionId::new("other"), event).as_json();
        assert_dropped(&mut fx, &foreign);
    }

    #[test]
    fn rejects_undecryptable_content() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let genuine = fx.response("ack");
        let event = UnsignedEvent::new(
            genuine.pubkey,
            genuine.created_at,
            Kind::NostrConnect,
            [Tag::public_key(fx.client.public_key())],
            "not-nip44",
        )
        .finalize(&fx.remote)
        .unwrap();
        assert_dropped(&mut fx, &frame(&event));
    }

    fn decrypted_params(fx: &Fx, event: &Event) -> Vec<String> {
        let plaintext = nip44::decrypt(
            fx.remote.secret_key(),
            &fx.client.public_key(),
            event.content.as_str(),
        )
        .unwrap();
        match NostrConnectMessage::from_json(&plaintext).unwrap() {
            NostrConnectMessage::Request { params, .. } => params,
            NostrConnectMessage::Response { .. } => unreachable!("expected a request"),
        }
    }

    fn wire(fx: &Fx, request: &NostrConnectRequest) -> Event {
        request_event(
            &fx.client,
            fx.remote.public_key(),
            &request_message(ID.to_owned(), request),
            Timestamp::from_secs(AT),
        )
        .unwrap()
    }

    #[test]
    fn connect_wire_params_are_exact() {
        let fx = Fx::new(NostrConnectMethod::Connect);
        let remote = fx.remote.public_key();
        let pair = Handshake::Pair {
            secret: Some("s3".into()),
        };
        let event = wire(&fx, &connect_request(&pair, remote));
        assert_eq!(
            decrypted_params(&fx, &event),
            [remote.to_hex(), "s3".to_owned(), CONNECT_PERMS.to_owned()]
        );
        let bare = Handshake::Pair { secret: None };
        let event = wire(&fx, &connect_request(&bare, remote));
        assert_eq!(
            decrypted_params(&fx, &event),
            [remote.to_hex(), String::new(), CONNECT_PERMS.to_owned()]
        );
        let message = request_message(ID.to_owned(), &connect_request(&pair, remote));
        assert_eq!(
            message.to_request().unwrap(),
            NostrConnectRequest::Connect {
                remote_signer_public_key: remote,
                secret: Some("s3".into()),
            }
        );
    }

    fn unsigned_json() -> String {
        r#"{"kind":1,"content":"hi","tags":[],"created_at":1700000000}"#.to_owned()
    }

    #[test]
    fn sign_event_param_is_a_json_string() {
        let fx = Fx::new(NostrConnectMethod::SignEvent);
        let unsigned = prepare(&unsigned_json(), fx.client.public_key()).unwrap();
        let event = wire(&fx, &NostrConnectRequest::SignEvent(unsigned.clone()));
        let params = decrypted_params(&fx, &event);
        assert_eq!(params.len(), 1);
        let parsed: UnsignedEvent = serde_json::from_str(params.first().unwrap()).unwrap();
        assert_eq!(parsed, unsigned);
    }

    #[test]
    fn sign_event_partial_form() {
        let session = Keys::generate().public_key();
        let filled = prepare(&unsigned_json(), session).unwrap();
        assert_eq!(filled.pubkey, session);
        let supplied = Keys::generate().public_key();
        let full = format!(
            r#"{{"pubkey":"{}","kind":1,"content":"hi","tags":[],"created_at":1700000000}}"#,
            supplied.to_hex()
        );
        assert!(matches!(
            prepare(&full, session),
            Err(NostrAuthError::SigningFailed(_))
        ));
        for bad in ["[1]", "\"x\"", "not json"] {
            assert!(matches!(
                prepare(bad, session),
                Err(NostrAuthError::Serialization(_))
            ));
        }
    }

    #[test]
    fn get_public_key_and_nip44_params() {
        let fx = Fx::new(NostrConnectMethod::GetPublicKey);
        let event = wire(&fx, &NostrConnectRequest::GetPublicKey);
        assert_eq!(decrypted_params(&fx, &event), Vec::<String>::new());
        let peer = Keys::generate().public_key();
        let encrypt = NostrConnectRequest::Nip44Encrypt {
            public_key: peer,
            text: "plain".into(),
        };
        let event = wire(&fx, &encrypt);
        assert_eq!(
            decrypted_params(&fx, &event),
            [peer.to_hex(), "plain".to_owned()]
        );
        let decrypt = NostrConnectRequest::Nip44Decrypt {
            public_key: peer,
            ciphertext: "cipher".into(),
        };
        let event = wire(&fx, &decrypt);
        assert_eq!(
            decrypted_params(&fx, &event),
            [peer.to_hex(), "cipher".to_owned()]
        );
    }

    #[test]
    fn frames_are_exact() {
        let client = Keys::generate().public_key();
        let req: serde_json::Value = serde_json::from_str(&subscribe_frame(client)).unwrap();
        assert_eq!(
            req,
            serde_json::json!([
                "REQ",
                SUBSCRIPTION_ID,
                {"kinds": [24133], "#p": [client.to_hex()]}
            ])
        );
        let fx = Fx::new(NostrConnectMethod::Connect);
        let event = wire(&fx, &NostrConnectRequest::GetPublicKey);
        let sent: serde_json::Value = serde_json::from_str(&event_frame(&event)).unwrap();
        assert_eq!(
            sent,
            serde_json::json!(["EVENT", serde_json::to_value(&event).unwrap()])
        );
    }

    #[test]
    fn connect_echoing_hex_secret_is_not_identity() {
        let echo = "ab".repeat(32);
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let event = fx.response(&echo);
        let result = only_outcome(fx.feed(&frame(&event))).unwrap();
        connect_result(result, Some(&echo)).unwrap();
        assert!(public_key_result(ResponseResult::ConnectSecret(echo)).is_err());
        let key = Keys::generate().public_key();
        assert_eq!(
            public_key_result(ResponseResult::GetPublicKey(key)).unwrap(),
            key
        );
    }

    #[test]
    fn connect_accepts_only_ack_or_the_echoed_secret() {
        let echo = |t: &str| ResponseResult::parse(NostrConnectMethod::Connect, t).unwrap();
        for text in ["denied", "unauthorized", "invalid secret", "no"] {
            assert!(
                connect_result(echo(text), Some("s3")).is_err(),
                "{text} accepted as ack"
            );
        }
        assert!(connect_result(echo("s3"), Some("s3")).is_ok());
        assert!(connect_result(echo("s3"), None).is_err());
        assert!(connect_result(ResponseResult::Ack, None).is_ok());
        assert!(
            connect_result(ResponseResult::ConnectSecret(String::new()), Some("")).is_err(),
            "empty reply accepted as paired"
        );
        for reply in ["bad secret s3", "bad s\u{200B}3"] {
            let refused = connect_result(echo(reply), Some("s3")).unwrap_err();
            assert!(
                !format!("{refused:?}").contains("s3"),
                "refusal quotes the secret: {refused:?}"
            );
        }
        let Err(RpcFailure::Signer(text)) = connect_result(echo("denied"), Some("s3")) else {
            unreachable!("refusal text lost");
        };
        assert_eq!(text, "denied");
    }

    #[test]
    fn connect_result_allow_list() {
        assert!(connect_result(ResponseResult::Ack, None).is_ok());
        assert!(connect_result(ResponseResult::ConnectSecret("s".into()), Some("s")).is_ok());
        assert!(connect_result(ResponseResult::ConnectSecret("s".into()), None).is_err());
        assert!(connect_result(ResponseResult::ConnectSecret(String::new()), None).is_err());
        assert!(connect_result(ResponseResult::ConnectSecret(String::new()), Some("")).is_err());
        for (literal, expect) in [("auth_url", "AuthUrl"), ("error", "Error")] {
            let mut fx = Fx::new(NostrConnectMethod::Connect);
            let event = fx.signed(&format!(
                r#"{{"id":"{ID}","result":"{literal}","error":null}}"#
            ));
            let result = only_outcome(fx.feed(&frame(&event))).unwrap();
            assert_eq!(expect == "AuthUrl", result.is_auth_url());
            assert!(matches!(
                connect_result(result, Some("s")),
                Err(RpcFailure::Malformed(_))
            ));
        }
    }

    #[test]
    fn get_public_key_off_curve_is_malformed() {
        let off_curve = "ff".repeat(32);
        let mut fx = Fx::new(NostrConnectMethod::GetPublicKey);
        let event = fx.response(&off_curve);
        let result = only_outcome(fx.feed(&frame(&event))).unwrap();
        assert!(matches!(
            public_key_result(result),
            Err(RpcFailure::Malformed(_))
        ));
    }

    #[test]
    fn get_public_key_non_hex_is_malformed() {
        let mut fx = Fx::new(NostrConnectMethod::GetPublicKey);
        let event = fx.response("nope");
        assert!(matches!(
            only_outcome(fx.feed(&frame(&event))),
            Err(RpcFailure::Malformed(_))
        ));
    }

    #[test]
    fn missing_result_is_error() {
        let bodies = [
            format!(r#"{{"id":"{ID}"}}"#),
            format!(r#"{{"id":"{ID}","result":null}}"#),
            format!(r#"{{"id":"{ID}","result":123}}"#),
            format!(r#"{{"id":"{ID}","error":123}}"#),
        ];
        for body in bodies {
            let mut fx = Fx::new(NostrConnectMethod::Connect);
            let event = fx.signed(&body);
            assert!(matches!(
                only_outcome(fx.feed(&frame(&event))),
                Err(RpcFailure::Malformed(MISSING_RESULT | MALFORMED_RESPONSE))
            ));
            assert!(!fx.pending());
        }
    }

    #[test]
    fn sanitizer_drops_all_format_characters() {
        for c in [
            '\u{061C}',
            '\u{180E}',
            '\u{FFF9}',
            '\u{E0001}',
            '\u{E0041}',
            '\u{2028}',
            '\u{2029}',
            '\u{3164}',
        ] {
            let out = sanitize_remote_text(&format!("a{c}b"));
            assert_eq!(out, "ab", "U+{:04X} kept", c as u32);
        }
    }

    #[test]
    fn signer_error_is_sanitised_and_capped() {
        let mut fx = Fx::new(NostrConnectMethod::SignEvent);
        let long = "x".repeat(500);
        let body = serde_json::json!({
            "id": ID,
            "error": format!("no\u{202E}pe\u{200B}\n{long}"),
        });
        let event = fx.signed(&body.to_string());
        let Err(RpcFailure::Signer(text)) = only_outcome(fx.feed(&frame(&event))) else {
            unreachable!("expected a signer failure");
        };
        assert!(text.starts_with("nopex"));
        assert_eq!(text.chars().count(), MAX_REMOTE_TEXT_CHARS);
    }

    #[test]
    fn nip44_encrypt_result_must_be_a_payload() {
        let (a, b) = (Keys::generate(), Keys::generate());
        let real =
            nip44::encrypt(a.secret_key(), &b.public_key(), "hi", nip44::Version::V2).unwrap();
        assert!(is_nip44_payload(&real));
        assert!(nip44_result(ResponseResult::Nip44Encrypt { ciphertext: real }).is_ok());
        for bad in [
            "meet at 9, the secret plan",
            "aGVsbG8=?iv=AAAAAAAAAAAAAAAAAAAAAA==",
            "",
        ] {
            let got = nip44_result(ResponseResult::Nip44Encrypt {
                ciphertext: bad.into(),
            });
            assert!(got.is_err(), "plaintext accepted as ciphertext: {bad}");
        }
    }

    #[test]
    fn nip44_plaintexts_come_back_literally() {
        for literal in ["error", "auth_url"] {
            let mut fx = Fx::new(NostrConnectMethod::Nip44Decrypt);
            let event = fx.response(literal);
            let result = only_outcome(fx.feed(&frame(&event))).unwrap();
            assert_eq!(nip44_result(result).unwrap(), literal);
        }
    }

    #[test]
    fn sign_event_result_is_shape_checked() {
        let inner = Keys::generate();
        let signed = UnsignedEvent::new(
            inner.public_key(),
            Timestamp::from_secs(AT),
            Kind::TextNote,
            [],
            "hi",
        )
        .finalize(&inner)
        .unwrap();
        let mut fx = Fx::new(NostrConnectMethod::SignEvent);
        let body = serde_json::json!({"id": ID, "result": signed.as_json()});
        let event = fx.signed(&body.to_string());
        let result = only_outcome(fx.feed(&frame(&event))).unwrap();
        assert_eq!(signed_event_result(result).unwrap(), signed.as_json());
        let mut fx = Fx::new(NostrConnectMethod::SignEvent);
        let event = fx.response("not an event");
        assert!(matches!(
            only_outcome(fx.feed(&frame(&event))),
            Err(RpcFailure::Malformed(_))
        ));
    }

    #[test]
    fn unknown_id_is_dropped() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let event = fx.signed(r#"{"id":"other","result":"ack"}"#);
        assert_dropped(&mut fx, &frame(&event));
        let event = fx.signed(r#"{"id":"other","result":123}"#);
        assert_dropped(&mut fx, &frame(&event));
    }

    #[test]
    fn replayed_response_settles_once() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let event = fx.response("ack");
        assert!(only_outcome(fx.feed(&frame(&event))).is_ok());
        assert!(fx.feed(&frame(&event)).is_empty());
    }

    fn auth_url_event(fx: &Fx, url: &str) -> Event {
        fx.signed(&serde_json::json!({"id": ID, "result": "auth_url", "error": url}).to_string())
    }

    const TOKEN_URL: &str = "https://signer.example/approve?token=SECRETTOKEN";

    fn only_prompt(mut effects: Vec<Effect<()>>) -> (String, HttpsUrl) {
        assert_eq!(effects.len(), 1);
        match effects.pop().unwrap() {
            Effect::Prompt { request_id, url } => (request_id, url),
            _ => unreachable!("expected a prompt"),
        }
    }

    #[test]
    fn auth_url_keeps_the_entry_and_a_later_response_completes_it() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let challenge = auth_url_event(&fx, TOKEN_URL);
        let (request_id, url) = only_prompt(fx.feed(&frame(&challenge)));
        assert_eq!(request_id, ID);
        assert_eq!(url.as_str(), TOKEN_URL);
        assert!(fx.pending());
        assert!(fx.auth_seen());
        let event = fx.response("ack");
        assert!(only_outcome(fx.feed(&frame(&event))).is_ok());
    }

    #[test]
    fn second_auth_url_replaces_the_first() {
        let mut fx = Fx::new(NostrConnectMethod::SignEvent);
        let mut prompts = PromptList::default();
        for url in [TOKEN_URL, "https://signer.example/second"] {
            let challenge = auth_url_event(&fx, url);
            let (id, url) = only_prompt(fx.feed(&frame(&challenge)));
            prompts.upsert(id, url);
        }
        assert_eq!(prompts.current(), Some("https://signer.example/second"));
        assert!(prompts.remove(ID));
        assert_eq!(prompts.current(), None);
    }

    #[test]
    fn href_is_the_parsed_form() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let challenge = auth_url_event(&fx, "HTTPS://Signer.Example/a b");
        let (_, url) = only_prompt(fx.feed(&frame(&challenge)));
        assert_eq!(url.as_str(), "https://signer.example/a%20b");
    }

    #[test]
    fn rejects_wrong_signature_on_auth_url() {
        assert!(matches!(
            Fx::new(NostrConnectMethod::Connect)
                .prompt_from_genuine_auth_url()
                .as_slice(),
            [Effect::Prompt { .. }]
        ));
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let other = fx.response("other");
        let mut forged = serde_json::to_value(auth_url_event(&fx, TOKEN_URL)).unwrap();
        set(&mut forged, "sig", serde_json::to_value(other.sig).unwrap());
        assert_dropped(&mut fx, &value_frame(&forged));
        assert!(!fx.auth_seen());
    }

    #[test]
    fn prompt_list_overlap() {
        let link = |path: &str| parse_auth_url(&format!("https://s.example/{path}")).unwrap();
        let mut prompts = PromptList::default();
        prompts.upsert("a".into(), link("a"));
        prompts.upsert("b".into(), link("b"));
        assert_eq!(prompts.current(), Some("https://s.example/b"));
        assert!(prompts.remove("b"));
        assert_eq!(prompts.current(), Some("https://s.example/a"));
        prompts.upsert("b".into(), link("b"));
        assert!(prompts.remove("a"));
        assert_eq!(prompts.current(), Some("https://s.example/b"));
        assert!(!prompts.remove("a"));
        prompts.upsert("a".into(), link("a"));
        prompts.remove_current();
        assert_eq!(prompts.current(), Some("https://s.example/b"));
    }

    #[test]
    fn auth_url_refusal_table() {
        let long = format!("https://signer.example/{}", "a".repeat(MAX_AUTH_URL_BYTES));
        let refused = [
            "http://signer.example/a",
            "javascript:alert(1)",
            "data:text/html,x",
            "/relative/path",
            "https://u:p@signer.example/",
            "https://u@signer.example/",
            "https://",
            long.as_str(),
        ];
        for url in refused {
            assert!(parse_auth_url(url).is_none(), "{url}");
            let mut fx = Fx::new(NostrConnectMethod::Connect);
            let event = auth_url_event(&fx, url);
            let Err(failure) = only_outcome(fx.feed(&frame(&event))) else {
                unreachable!("expected a refusal");
            };
            let text = failure.into_connect_error().to_string();
            assert!(!text.contains("signer.example") && !text.contains("alert"));
            assert!(!fx.pending());
        }
        assert!(parse_auth_url(TOKEN_URL).is_some());
    }

    #[test]
    fn auth_url_host_table() {
        assert_eq!(
            auth_url_host("https://xn--80ak6aa92e.com/a?b").as_deref(),
            Some("xn--80ak6aa92e.com")
        );
        assert_eq!(auth_url_host("not a url"), None);
    }

    fn seen(fx: &mut Fx) {
        let challenge = auth_url_event(fx, TOKEN_URL);
        let _ = fx.feed(&frame(&challenge));
        assert!(fx.auth_seen());
    }

    #[test]
    fn deadline_table() {
        let no_answer = DeadlineAction::Timeout {
            signer_answered: false,
        };
        let answered = DeadlineAction::Timeout {
            signer_answered: true,
        };
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        assert_eq!(fx.inflight.on_deadline(ID, true), no_answer);
        assert_eq!(fx.inflight.on_deadline(ID, false), no_answer);
        seen(&mut fx);
        assert_eq!(
            fx.inflight.on_deadline(ID, false),
            DeadlineAction::AuthRequired
        );
        assert_eq!(fx.inflight.on_deadline(ID, true), DeadlineAction::Extend);
        assert_eq!(
            fx.inflight.on_deadline(ID, false),
            DeadlineAction::AuthRequired
        );
        seen(&mut fx);
        assert_eq!(fx.inflight.on_deadline(ID, true), answered);
        assert_eq!(fx.inflight.on_deadline("missing", true), no_answer);
    }

    #[test]
    fn timeout_after_auth_url_does_not_advance() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        seen(&mut fx);
        assert_eq!(fx.inflight.on_deadline(ID, true), DeadlineAction::Extend);
        let DeadlineAction::Timeout { signer_answered } = fx.inflight.on_deadline(ID, true) else {
            unreachable!("expected a timeout");
        };
        let failure = fx.inflight.timeout_failure(signer_answered);
        assert!(!failure.advances_to_next_relay());
        assert!(matches!(
            failure.into_connect_error(),
            NostrAuthError::BunkerTimeout
        ));
        assert!(fx.inflight.timeout_failure(false).advances_to_next_relay());
    }

    fn ok_false(event_id: EventId) -> String {
        RelayMessage::ok(event_id, false, "blocked: mock").as_json()
    }

    fn closed(subscription: &str) -> String {
        RelayMessage::closed(SubscriptionId::new(subscription), "blocked: mock").as_json()
    }

    fn relay_failure(outcome: Result<ResponseResult, RpcFailure>) -> (String, bool, bool) {
        let Err(failure) = outcome else {
            unreachable!("expected a failure");
        };
        let advances = failure.advances_to_next_relay();
        let RpcFailure::Relay {
            reason,
            signer_answered,
        } = failure
        else {
            unreachable!("expected a relay failure");
        };
        (reason, signer_answered, advances)
    }

    #[test]
    fn relay_failure_after_auth_url_does_not_advance() {
        let id = other_event_id();
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        seen(&mut fx);
        let (reason, answered, advances) = relay_failure(only_outcome(fx.feed(&ok_false(id))));
        assert_eq!(reason, "blocked: mock");
        assert!(answered && !advances);

        let mut fx = Fx::new(NostrConnectMethod::Connect);
        let (_, answered, advances) = relay_failure(only_outcome(fx.feed(&ok_false(id))));
        assert!(!answered && advances);

        let mut fx = Fx::new(NostrConnectMethod::Connect);
        fx.inflight.insert(
            "req-2".to_owned(),
            NostrConnectMethod::SignEvent,
            EventId::from_byte_array([8; 32]),
            (),
        );
        seen(&mut fx);
        let effects = fx.feed(&closed(SUBSCRIPTION_ID));
        assert_eq!(effects.len(), 3);
        let mut answered = Vec::new();
        for effect in effects {
            if let Effect::Settle { outcome, .. } = effect {
                let (reason, signer_answered, advances) = relay_failure(outcome);
                assert_eq!(reason, "blocked: mock");
                assert_eq!(signer_answered, !advances);
                answered.push(signer_answered);
            }
        }
        answered.sort_unstable();
        assert_eq!(answered, [false, true]);
    }

    #[test]
    fn auth_required_does_not_advance_relay() {
        assert!(!RpcFailure::AuthRequired.advances_to_next_relay());
        let mut log = AttemptLog::default();
        assert!(
            log.record(RpcFailure::Relay {
                reason: "earlier".into(),
                signer_answered: false,
            })
            .is_none()
        );
        let stopped = log.record(RpcFailure::AuthRequired).unwrap();
        assert!(matches!(
            stopped.into_connect_error(),
            NostrAuthError::BunkerAuthRequired
        ));
        assert!(matches!(
            RpcFailure::AuthRequired.into_signing_error(),
            NostrAuthError::BunkerAuthRequired
        ));
    }

    #[test]
    fn auth_required_text_has_no_url() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        seen(&mut fx);
        assert_eq!(
            fx.inflight.on_deadline(ID, false),
            DeadlineAction::AuthRequired
        );
        let failure = RpcFailure::AuthRequired;
        let error = NostrAuthError::BunkerAuthRequired;
        for text in [
            format!("{failure:?}"),
            error.to_string(),
            format!("{error:?}"),
        ] {
            assert!(!text.contains("SECRETTOKEN") && !text.contains("signer.example"));
        }
    }

    #[test]
    fn late_response_settles_ok_without_presenter() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        seen(&mut fx);
        let event = fx.response("ack");
        assert!(only_outcome(fx.feed(&frame(&event))).is_ok());
    }

    #[test]
    fn ok_false_needs_matching_event_id() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        assert_dropped(&mut fx, &ok_false(EventId::from_byte_array([9; 32])));
        let accepted = RelayMessage::ok(other_event_id(), true, "").as_json();
        assert_dropped(&mut fx, &accepted);
        let (reason, _, _) = relay_failure(only_outcome(fx.feed(&ok_false(other_event_id()))));
        assert_eq!(reason, "blocked: mock");
    }

    #[test]
    fn closed_fails_all_on_our_subscription_only() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        assert_dropped(&mut fx, &closed("other"));
        let effects = fx.feed(&closed(SUBSCRIPTION_ID));
        assert_eq!(effects.len(), 2);
        assert!(effects.iter().any(|e| matches!(e, Effect::CloseSocket)));
        assert!(!fx.pending());
    }

    #[test]
    fn auth_frame_fails_nothing_and_names_nip42_on_timeout() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        assert_dropped(&mut fx, &RelayMessage::auth("challenge").as_json());
        let text = fx
            .inflight
            .timeout_failure(false)
            .into_connect_error()
            .to_string();
        assert!(
            text.contains("did not answer") && text.contains("NIP-42"),
            "{text}"
        );
        assert!(!text.contains("challenge"));
        fx.inflight.reset_socket();
        assert!(matches!(
            fx.inflight.timeout_failure(false).into_signing_error(),
            NostrAuthError::BunkerTimeout
        ));
    }

    #[test]
    fn nip42_named_only_for_auth_required_refusals() {
        let timeout = RpcFailure::Timeout {
            signer_answered: false,
            relay_asked_auth: true,
        }
        .into_signing_error()
        .to_string();
        assert!(timeout.contains("did not answer"), "{timeout}");
        let refused = RpcFailure::Relay {
            reason: "auth-required: sign in first".into(),
            signer_answered: false,
        }
        .into_signing_error()
        .to_string();
        assert!(refused.contains("requires NIP-42"), "{refused}");
    }

    #[test]
    fn garbage_frames_do_nothing() {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        for garbage in [
            "",
            "not json",
            "[]",
            "{}",
            "[\"EVENT\"]",
            "[\"EVENT\",1,2]",
            "[\"OK\",\"xx\",false,\"m\"]",
            "[\"CLOSED\",1,2]",
            "[\"AUTH\",1]",
            "[\"NOTICE\",\"hello\"]",
            "[\"EOSE\",\"nip46-persistent\"]",
        ] {
            assert_dropped(&mut fx, garbage);
        }
    }

    fn uri(fx_remote: &PublicKey, query: &str) -> String {
        format!("bunker://{}?{query}", fx_remote.to_hex())
    }

    #[test]
    fn two_relays_retained_in_order_without_duplicates() {
        let remote = Keys::generate().public_key();
        let target = parse_bunker_uri(&uri(
            &remote,
            "relay=wss%3A%2F%2Fa.example&relay=wss%3A%2F%2Fb.example&relay=wss%3A%2F%2Fa.example",
        ))
        .unwrap();
        let listed: Vec<&str> = target.relays.iter().map(RelayUrl::as_str).collect();
        assert_eq!(listed, ["wss://a.example", "wss://b.example"]);
        assert_eq!(target.remote, remote);
    }

    #[test]
    fn bunker_uri_refuses_plaintext_relay() {
        let remote = Keys::generate().public_key().to_hex();
        let uri = format!("bunker://{remote}?relay=ws%3A%2F%2Frelay.example.com");
        assert!(parse_bunker_uri(&uri).is_err(), "ws:// relay accepted");
        let local = format!("bunker://{remote}?relay=ws%3A%2F%2Flocalhost%3A7777");
        assert!(parse_bunker_uri(&local).is_ok(), "loopback relay refused");
    }

    fn relay_query(count: usize) -> String {
        (0..count)
            .map(|n| format!("relay=wss%3A%2F%2Fr{n}.example"))
            .collect::<Vec<_>>()
            .join("&")
    }

    #[test]
    fn relay_cap() {
        let remote = Keys::generate().public_key();
        assert!(parse_bunker_uri(&uri(&remote, &relay_query(5))).is_ok());
        let refused = uri(&remote, &format!("{}&secret=hush", relay_query(6)));
        let text = parse_bunker_uri(&refused).err().unwrap().to_string();
        assert!(text.contains("too many relays, the limit is 5"));
        assert!(!text.contains("hush") && !text.contains("r0.example"));
        let dup = format!("{}&relay=wss%3A%2F%2Fr0.example", relay_query(5));
        assert!(parse_bunker_uri(&uri(&remote, &dup)).is_ok());
    }

    #[test]
    fn persisted_uri_round_trips_without_secret() {
        let remote = Keys::generate().public_key();
        let target = parse_bunker_uri(&uri(
            &remote,
            "relay=wss%3A%2F%2Fa.example&relay=ws%3A%2F%2Flocalhost%2Fpath&secret=hush",
        ))
        .unwrap();
        let stored = persisted_uri(&target.remote, &target.relays).unwrap();
        assert!(!stored.contains("hush") && !stored.contains("secret"));
        let again = parse_bunker_uri(&stored).unwrap();
        assert_eq!(again.relays, target.relays);
        assert!(again.secret.is_none());
    }

    #[test]
    fn stored_uri_secret_is_ignored() {
        let remote = Keys::generate().public_key();
        let target =
            parse_bunker_uri(&uri(&remote, "relay=wss%3A%2F%2Fa.example&secret=hush")).unwrap();
        assert!(!needs_connect(&Handshake::Restore, false));
        let request = connect_request(&Handshake::Restore, remote);
        assert_eq!(
            request,
            NostrConnectRequest::Connect {
                remote_signer_public_key: remote,
                secret: None,
            }
        );
        let stored = persisted_uri(&target.remote, &target.relays).unwrap();
        assert!(!stored.contains("hush"));
    }

    #[test]
    fn single_relay_form_is_byte_equal() {
        let remote = Keys::generate().public_key();
        let relays = [RelayUrl::parse("wss://relay.example").unwrap()];
        assert_eq!(
            persisted_uri(&remote, &relays).unwrap(),
            format!(
                "bunker://{}?relay=wss%3A%2F%2Frelay.example",
                remote.to_hex()
            )
        );
    }

    #[test]
    fn working_relay_moves_to_front() {
        let a = RelayUrl::parse("wss://a.example").unwrap();
        let b = RelayUrl::parse("wss://b.example").unwrap();
        let mut relays = vec![a.clone(), b.clone()];
        rotate_to_front(&mut relays, &b);
        assert_eq!(relays, [b, a]);
    }

    #[test]
    fn bad_uri_errors_never_contain_the_secret() {
        let remote = Keys::generate().public_key();
        for bad in [
            "bunker://nothex?relay=wss%3A%2F%2Fa.example&secret=hush".to_owned(),
            uri(&remote, "relay=https%3A%2F%2Fa.example&secret=hush"),
            uri(&remote, "secret=hush"),
            "bunker://?secret=hush".to_owned(),
            "other://x?secret=hush".to_owned(),
        ] {
            let text = parse_bunker_uri(&bad).err().unwrap().to_string();
            assert!(!text.contains("hush"), "{text}");
        }
    }

    #[test]
    fn bunker_uri_rejects_off_curve_remote() {
        let bad = crate::signers::signer_traits::tests::off_curve();
        let got = parse_bunker_uri(&uri(&bad, "relay=wss%3A%2F%2Fa.example&secret=hush"));
        let text = got.err().unwrap().to_string();
        assert_eq!(text, "Invalid bunker URI: invalid URI");
    }

    #[test]
    fn uppercase_hex_accepted() {
        let remote = Keys::generate().public_key();
        let upper = format!(
            "bunker://{}?relay=wss%3A%2F%2Fa.example",
            remote.to_hex().to_uppercase()
        );
        assert_eq!(parse_bunker_uri(&upper).unwrap().remote, remote);
    }

    #[test]
    fn uri_error_texts_unchanged() {
        let remote = Keys::generate().public_key();
        let text = |input: &str| parse_bunker_uri(input).err().unwrap().to_string();
        assert!(text("nostrconnect://x").contains("nostrconnect:// (client-initiated pairing)"));
        assert_eq!(
            text("hello"),
            "Invalid bunker URI: URI must start with bunker://"
        );
        assert_eq!(
            text(&format!("bunker://{}", remote.to_hex())),
            "Invalid bunker URI: missing relay URL"
        );
    }

    #[test]
    fn advances_to_next_relay_table() {
        let socket = || RpcFailure::Socket(NostrAuthError::BunkerTimeout);
        let timeout = |signer_answered, relay_asked_auth| RpcFailure::Timeout {
            signer_answered,
            relay_asked_auth,
        };
        let relay = |signer_answered| RpcFailure::Relay {
            reason: "r".into(),
            signer_answered,
        };
        for (failure, advances) in [
            (timeout(false, false), true),
            (timeout(false, true), true),
            (timeout(true, false), false),
            (timeout(true, true), false),
            (RpcFailure::AuthRequired, false),
            (socket(), true),
            (
                RpcFailure::SocketLost {
                    signer_answered: false,
                    replaced: false,
                },
                true,
            ),
            (
                RpcFailure::SocketLost {
                    signer_answered: true,
                    replaced: false,
                },
                false,
            ),
            (relay(false), true),
            (relay(true), false),
            (RpcFailure::Signer("s".into()), false),
            (RpcFailure::Malformed("m"), false),
        ] {
            assert_eq!(failure.advances_to_next_relay(), advances);
        }
    }

    #[test]
    fn failure_mapping_differs_for_malformed_and_signer() {
        assert!(matches!(
            RpcFailure::Malformed("m").into_connect_error(),
            NostrAuthError::BunkerConnectionFailed(_)
        ));
        assert!(matches!(
            RpcFailure::Malformed("m").into_signing_error(),
            NostrAuthError::SigningFailed(_)
        ));
        let signer = RpcFailure::Signer("denied".into()).into_signing_error();
        assert_eq!(signer.to_string(), "Signing failed: denied");
        let login = RpcFailure::Signer("denied".into()).into_connect_error();
        assert_eq!(login.to_string(), "Bunker connection failed: denied");
        assert!(matches!(
            RpcFailure::Malformed("m").into_encryption_error(),
            NostrAuthError::EncryptionFailed(text) if text == "m"
        ));
        assert!(matches!(
            RpcFailure::Signer("denied".into()).into_encryption_error(),
            NostrAuthError::EncryptionFailed(text) if text == "denied"
        ));
        assert!(matches!(
            RpcFailure::SessionClosed.into_encryption_error(),
            NostrAuthError::BunkerSessionClosed
        ));
        assert!(matches!(
            RpcFailure::AuthRequired.into_encryption_error(),
            NostrAuthError::BunkerAuthRequired
        ));
        assert!(matches!(
            RpcFailure::Timeout {
                signer_answered: true,
                relay_asked_auth: false
            }
            .into_encryption_error(),
            NostrAuthError::BunkerTimeout
        ));
        assert!(matches!(
            RpcFailure::Socket(NostrAuthError::BunkerSessionClosed).into_encryption_error(),
            NostrAuthError::BunkerSessionClosed
        ));
        assert!(matches!(
            RpcFailure::SocketLost {
                signer_answered: false,
                replaced: false
            }
            .into_encryption_error(),
            NostrAuthError::BunkerConnectionFailed(_)
        ));
        assert!(matches!(
            RpcFailure::Relay {
                reason: "no".into(),
                signer_answered: false
            }
            .into_encryption_error(),
            NostrAuthError::BunkerConnectionFailed(_)
        ));
    }

    #[test]
    fn signer_text_timeout_stays_signer_text() {
        let mut fx = Fx::new(NostrConnectMethod::SignEvent);
        let event = fx.signed(&serde_json::json!({"id": ID, "error": "timeout"}).to_string());
        let Err(failure) = only_outcome(fx.feed(&frame(&event))) else {
            unreachable!("expected a failure");
        };
        let RpcFailure::Signer(signer_text) = &failure else {
            unreachable!("expected a signer failure");
        };
        assert_eq!(signer_text, "timeout");
        let NostrAuthError::SigningFailed(text) = failure.into_signing_error() else {
            unreachable!("expected a signing failure");
        };
        assert_eq!(text, "timeout");
    }

    fn with_sibling() -> Fx {
        let mut fx = Fx::new(NostrConnectMethod::Connect);
        fx.inflight.insert(
            "req-2".to_owned(),
            NostrConnectMethod::SignEvent,
            EventId::from_byte_array([8; 32]),
            (),
        );
        fx
    }

    #[test]
    fn socket_loss_keeps_signer_answered_per_entry() {
        let mut fx = with_sibling();
        seen(&mut fx);
        let mut flags = Vec::new();
        for effect in fx.inflight.fail_socket_lost() {
            let Effect::Settle {
                outcome: Err(failure),
                ..
            } = effect
            else {
                unreachable!("expected a failure");
            };
            let advances = failure.advances_to_next_relay();
            let RpcFailure::SocketLost {
                signer_answered, ..
            } = failure
            else {
                unreachable!("expected a lost socket");
            };
            assert_eq!(signer_answered, !advances);
            flags.push(signer_answered);
        }
        flags.sort_unstable();
        assert_eq!(flags, [false, true]);
    }

    #[test]
    fn socket_loss_is_not_a_relay_reason() {
        for signer_answered in [false, true] {
            let lost = || RpcFailure::SocketLost {
                signer_answered,
                replaced: false,
            };
            for error in [lost().into_connect_error(), lost().into_signing_error()] {
                let NostrAuthError::BunkerConnectionFailed(text) = error else {
                    unreachable!("expected a connection failure");
                };
                assert_eq!(text, "relay connection lost");
            }
        }
    }

    #[test]
    fn socket_loss_yields_only_failures() {
        let mut fx = with_sibling();
        seen(&mut fx);
        let effects = fx.inflight.fail_socket_lost();
        assert_eq!(effects.len(), 2);
        assert!(effects.iter().all(|effect| matches!(
            effect,
            Effect::Settle {
                outcome: Err(RpcFailure::SocketLost { .. }),
                ..
            }
        )));
        assert!(fx.inflight.entries.is_empty());
    }

    #[test]
    fn fail_all_still_reports_the_relay() {
        let mut fx = with_sibling();
        seen(&mut fx);
        let mut flags = Vec::new();
        for effect in fx.inflight.fail_all("blocked: mock") {
            let Effect::Settle { outcome, .. } = effect else {
                unreachable!("expected a settle");
            };
            let (reason, answered, _) = relay_failure(outcome);
            assert_eq!(reason, "blocked: mock");
            flags.push(answered);
        }
        flags.sort_unstable();
        assert_eq!(flags, [false, true]);
    }

    fn timeout_failure() -> RpcFailure {
        RpcFailure::Timeout {
            signer_answered: false,
            relay_asked_auth: false,
        }
    }

    #[test]
    fn note_settled_table() {
        let plain = |marked: bool| {
            let mut fx = Fx::new(NostrConnectMethod::SignEvent);
            fx.inflight.suspect = marked;
            fx
        };
        let empty = |marked: bool| {
            let mut fx = plain(marked);
            fx.inflight.remove(ID);
            fx
        };
        let auth = |marked: bool| {
            let mut fx = plain(marked);
            seen(&mut fx);
            fx
        };
        let fixtures: [(&str, &dyn Fn(bool) -> Fx); 3] =
            [("empty", &empty), ("plain", &plain), ("auth", &auth)];
        for marked in [false, true] {
            for (table, fixture) in fixtures {
                let mut fx = fixture(marked);
                assert!(!fx.inflight.note_settled(None));
                assert!(!fx.inflight.suspect, "ok on {table}");

                let mut fx = fixture(marked);
                assert!(
                    !fx.inflight
                        .note_settled(Some(&RpcFailure::Signer("no".into())))
                );
                assert!(!fx.inflight.suspect, "signer on {table}");

                let mut fx = fixture(marked);
                let tears_down = fx.inflight.note_settled(Some(&timeout_failure()));
                assert_eq!(tears_down, table == "empty");
                assert_eq!(fx.inflight.suspect, marked || table != "empty");

                for failure in [RpcFailure::AuthRequired, RpcFailure::Malformed("m")] {
                    let mut fx = fixture(marked);
                    assert!(!fx.inflight.note_settled(Some(&failure)));
                    assert!(!fx.inflight.suspect, "{failure:?} on {table}");
                }

                let mut fx = fixture(marked);
                assert!(!fx.inflight.note_settled(Some(&RpcFailure::Timeout {
                    signer_answered: true,
                    relay_asked_auth: false,
                })));
                assert!(!fx.inflight.suspect, "answered timeout on {table}");

                for failure in [
                    RpcFailure::Build,
                    RpcFailure::Relay {
                        reason: "r".into(),
                        signer_answered: false,
                    },
                    RpcFailure::SocketLost {
                        signer_answered: false,
                        replaced: false,
                    },
                    RpcFailure::Socket(NostrAuthError::BunkerTimeout),
                ] {
                    let mut fx = fixture(marked);
                    assert!(!fx.inflight.note_settled(Some(&failure)));
                    assert_eq!(fx.inflight.suspect, marked, "{failure:?} on {table}");
                }
            }
        }
    }

    #[test]
    fn must_reconnect_table() {
        let mut fx = Fx::new(NostrConnectMethod::SignEvent);
        assert!(!fx.inflight.must_reconnect());
        fx.inflight.suspect = true;
        assert!(fx.inflight.must_reconnect());
        seen(&mut fx);
        assert!(!fx.inflight.must_reconnect());
        fx.inflight.remove(ID);
        assert!(fx.inflight.must_reconnect());
    }

    #[test]
    fn reset_socket_clears_suspect() {
        let mut fx = Fx::new(NostrConnectMethod::SignEvent);
        fx.inflight.suspect = true;
        fx.inflight.reset_socket();
        assert!(!fx.inflight.suspect);
    }

    /// Records its outcome, and can rejoin the gate from inside `wake`.
    struct TestWaker {
        seen: Rc<RefCell<Vec<ReconnectOutcome>>>,
        rejoin: Option<Rc<ReconnectGate<Self>>>,
    }

    impl ReconnectWaker for TestWaker {
        fn wake(self, outcome: ReconnectOutcome) {
            self.seen.borrow_mut().push(outcome);
            if let Some(gate) = self.rejoin {
                let lead = gate.join(Self {
                    seen: Rc::clone(&self.seen),
                    rejoin: None,
                });
                assert!(lead.is_some());
            }
        }
    }

    type Seen = Rc<RefCell<Vec<ReconnectOutcome>>>;

    fn gate_fixture() -> (Rc<ReconnectGate<TestWaker>>, Seen) {
        (Rc::default(), Rc::default())
    }

    fn follower(seen: &Seen) -> TestWaker {
        TestWaker {
            seen: Rc::clone(seen),
            rejoin: None,
        }
    }

    #[test]
    fn dropped_lead_wakes_followers_and_clears_gate() {
        let (gate, seen) = gate_fixture();
        let lead = gate.join(follower(&seen)).unwrap();
        assert!(gate.join(follower(&seen)).is_none());
        assert!(gate.join(follower(&seen)).is_none());
        drop(lead);
        let seen = seen.borrow();
        assert_eq!(seen.len(), 2);
        for outcome in seen.iter() {
            let Err(NostrAuthError::BunkerConnectionFailed(text)) = outcome else {
                unreachable!("expected a connection failure");
            };
            assert_eq!(text, "reconnect cancelled");
        }
        drop(seen);
        assert!(gate.join(follower(&Seen::default())).is_some());
    }

    #[test]
    fn finished_lead_passes_error_by_value() {
        for error in [
            NostrAuthError::BunkerTimeout,
            NostrAuthError::BunkerAuthRequired,
            NostrAuthError::BunkerConnectionFailed("x".into()),
        ] {
            let (gate, seen) = gate_fixture();
            let lead = gate.join(follower(&seen)).unwrap();
            assert!(gate.join(follower(&seen)).is_none());
            lead.finish(Err(error.clone()));
            let seen = seen.borrow();
            let Some(Err(got)) = seen.first() else {
                unreachable!("expected one failure");
            };
            assert_eq!(
                core::mem::discriminant(got),
                core::mem::discriminant(&error)
            );
            assert_eq!(got.to_string(), error.to_string());
            assert!(got.to_string().matches("Bunker connection failed:").count() <= 1);
        }
    }

    #[test]
    fn finished_lead_passes_ok() {
        let (gate, seen) = gate_fixture();
        let lead = gate.join(follower(&seen)).unwrap();
        assert!(gate.join(follower(&seen)).is_none());
        lead.finish(Ok(()));
        assert!(matches!(seen.borrow().as_slice(), [Ok(())]));
    }

    #[test]
    fn second_join_follows() {
        let (gate, seen) = gate_fixture();
        let lead = gate.join(follower(&seen));
        assert!(lead.is_some());
        assert!(gate.join(follower(&seen)).is_none());
        assert!(seen.borrow().is_empty());
    }

    #[test]
    fn wake_may_rejoin_the_gate() {
        let (gate, seen) = gate_fixture();
        let lead = gate.join(follower(&seen)).unwrap();
        let rejoining = TestWaker {
            seen: Rc::clone(&seen),
            rejoin: Some(Rc::clone(&gate)),
        };
        assert!(gate.join(rejoining).is_none());
        lead.finish(Ok(()));
        assert_eq!(seen.borrow().len(), 1);
    }

    #[test]
    fn later_relays_skip_connect_after_ack() {
        let pair = Handshake::Pair { secret: None };
        assert!(needs_connect(&pair, false));
        assert!(!needs_connect(&pair, true));
        assert!(!needs_connect(&Handshake::Restore, false));
        assert!(!needs_connect(&Handshake::Restore, true));
    }

    #[test]
    fn final_error_prefers_a_relay_reason_when_exhausted() {
        let mut log = AttemptLog::default();
        assert!(
            log.record(RpcFailure::Relay {
                reason: "first".into(),
                signer_answered: false,
            })
            .is_none()
        );
        assert!(
            log.record(RpcFailure::Socket(NostrAuthError::BunkerTimeout))
                .is_none()
        );
        assert!(matches!(log.finish(), RpcFailure::Relay { reason, .. } if reason == "first"));
        let mut log = AttemptLog::default();
        assert!(
            log.record(RpcFailure::Socket(NostrAuthError::BunkerTimeout))
                .is_none()
        );
        assert!(matches!(log.finish(), RpcFailure::Socket(_)));
        let stopped = AttemptLog::default().record(RpcFailure::Signer("no".into()));
        assert!(matches!(stopped, Some(RpcFailure::Signer(_))));
    }

    fn two_entries_one_auth_seen() -> Inflight<()> {
        let mut inflight = Inflight::default();
        for id in ["a", "b"] {
            inflight.insert(
                id.to_owned(),
                NostrConnectMethod::SignEvent,
                other_event_id(),
                (),
            );
        }
        inflight.entries.get_mut("b").unwrap().auth_seen = true;
        inflight
    }

    #[test]
    fn session_closed_fails_every_entry() {
        let mut inflight = two_entries_one_auth_seen();
        let effects = inflight.fail_session_closed();
        assert_eq!(effects.len(), 2);
        for effect in effects {
            assert!(matches!(
                effect,
                Effect::Settle {
                    outcome: Err(RpcFailure::SessionClosed),
                    ..
                }
            ));
        }
        assert!(inflight.entries.is_empty());
    }

    #[test]
    fn session_closed_does_not_advance() {
        assert!(!RpcFailure::SessionClosed.advances_to_next_relay());
        let stopped = AttemptLog::default().record(RpcFailure::SessionClosed);
        assert!(matches!(stopped, Some(RpcFailure::SessionClosed)));
    }

    #[test]
    fn session_closed_maps_to_variant() {
        let text = "Bunker session closed by logout or replacement";
        for error in [
            RpcFailure::SessionClosed.into_connect_error(),
            RpcFailure::SessionClosed.into_signing_error(),
        ] {
            assert!(matches!(error, NostrAuthError::BunkerSessionClosed));
            assert_eq!(error.to_string(), text);
        }
    }

    #[test]
    fn session_closed_passes_through_followers() {
        let (gate, seen) = gate_fixture();
        let lead = gate.join(follower(&seen)).unwrap();
        assert!(gate.join(follower(&seen)).is_none());
        lead.finish(Err(RpcFailure::SessionClosed.into_connect_error()));
        assert!(matches!(
            seen.borrow().as_slice(),
            [Err(NostrAuthError::BunkerSessionClosed)]
        ));
    }

    #[test]
    fn session_closed_leaves_suspect_alone() {
        let mut inflight = two_entries_one_auth_seen();
        assert!(!inflight.note_settled(Some(&RpcFailure::SessionClosed)));
        assert!(!inflight.suspect);
    }

    #[test]
    fn response_after_close_is_inert() {
        let mut fx = Fx::new(NostrConnectMethod::SignEvent);
        let response = fx.response("ack");
        assert_eq!(fx.inflight.fail_session_closed().len(), 1);
        assert!(fx.feed(&frame(&response)).is_empty());
    }

    fn two_pending() -> Inflight<()> {
        let mut inflight = Inflight::default();
        for (id, byte) in [("a", 1), ("b", 2)] {
            inflight.insert(
                id.to_owned(),
                NostrConnectMethod::SignEvent,
                EventId::from_byte_array([byte; 32]),
                (),
            );
        }
        inflight
    }

    #[test]
    fn expired_approval_does_not_mark_socket_suspect() {
        let mut inflight = two_pending();
        let failure = RpcFailure::Timeout {
            signer_answered: true,
            relay_asked_auth: false,
        };
        assert!(!inflight.note_settled(Some(&failure)));
        assert!(
            !inflight.must_reconnect(),
            "healthy socket marked for reconnect"
        );
        let mut alone = Inflight::<()>::default();
        assert!(
            !alone.note_settled(Some(&failure)),
            "healthy socket torn down"
        );
    }

    #[test]
    fn verified_answers_clear_suspect() {
        for proof in [RpcFailure::Malformed("x"), RpcFailure::AuthRequired] {
            let mut inflight = two_pending();
            inflight.note_settled(Some(&timeout_failure()));
            inflight.note_settled(Some(&proof));
            assert!(
                !inflight.must_reconnect(),
                "suspect survived a verified answer"
            );
        }
    }

    #[test]
    fn local_build_failure_keeps_suspect() {
        let mut inflight = two_pending();
        inflight.note_settled(Some(&timeout_failure()));
        inflight.note_settled(Some(&RpcFailure::Build));
        assert!(inflight.must_reconnect());
    }

    #[test]
    fn replaced_socket_says_the_signer_may_answer() {
        let mut inflight = two_pending();
        let mut effects = inflight.fail_socket_replaced();
        let Some(Effect::Settle {
            outcome: Err(failure),
            ..
        }) = effects.pop()
        else {
            unreachable!("no settle");
        };
        let text = failure.into_signing_error().to_string();
        assert!(text.contains("may still"), "{text}");
    }

    #[test]
    fn oversized_frame_is_dropped() {
        let (client, remote) = (Keys::generate(), Keys::generate());
        let peer = Peer {
            client,
            remote: remote.public_key(),
        };
        let id = EventId::from_byte_array([1; 32]);
        let mut inflight = Inflight::default();
        inflight.insert("a".into(), NostrConnectMethod::SignEvent, id, ());
        let frame = format!(
            r#"["OK","{}",false,"{}"]"#,
            id.to_hex(),
            "x".repeat(300_000)
        );
        assert!(
            inflight.on_frame(&frame, &peer).is_empty(),
            "oversized frame was parsed"
        );
    }
}
