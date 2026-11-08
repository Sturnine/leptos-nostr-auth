use nostr::key::{Keys, PublicKey};
use nostr::types::RelayUrl;

use crate::types::NostrAuthError;

/// An established NIP-46 remote signing session.
///
/// One WebSocket carries the handshake and every later request. Every relay in the URI is kept;
/// connection tries them in order until one works, and the one that worked moves to the front of
/// [`BunkerSession::bunker_uri`]. There is no failover while a socket stays open, because retrying
/// a `sign_event` elsewhere risks signing twice.
///
/// `Clone` is shallow: every clone shares one connection, so clones from repeated reads of a
/// reactive `Signal<AuthResult>` refer to one physical socket, not independent snapshots.
/// Concurrent reconnects across clones share one attempt.
///
/// The connection closes when the last clone drops, and when a [`crate::context::NostrAuthProvider`]
/// logs out or replaces this session. Closing by the provider is final for every clone: see
/// [`NostrAuthError::BunkerSessionClosed`].
#[derive(Clone)]
#[cfg_attr(
    feature = "ssr",
    expect(dead_code, reason = "these fields are read only by the browser build")
)]
pub struct BunkerSession {
    /// The authenticated user's public key.
    pub public_key: PublicKey,
    /// Stored for session restore
    pub bunker_uri: String,
    timeout_secs: u32,
    client_keys: Keys,
    remote_pubkey: PublicKey,
    /// Relays to try, working relay first.
    relays: Vec<RelayUrl>,
    #[cfg(not(feature = "ssr"))]
    conn: send_wrapper::SendWrapper<std::rc::Rc<imp::Connection>>,
}

impl BunkerSession {
    /// Establish a NIP-46 connection from a `bunker://` URI (fresh login).
    ///
    /// Generates a new ephemeral local pairing keypair for this session.
    ///
    /// A URI may list up to five relays after duplicates are removed. If the signer sends an
    /// approval link, a mounted [`crate::modal::NostrAuthModal`] shows it, also while `open` is
    /// false, and that request waits one extra 300 s. A login with `n` relays can take up to
    /// `(2n+1) * timeout_secs + 600` seconds. For a direct call, a modal unmounted during that wait
    /// does not shorten it. A lost socket ends a wait, including one for approval, which then needs
    /// a retry, as soon as the browser reports the close. A relay's close frame with TCP held open
    /// can wait for the browser's grace period or a new request, bounded by the request's deadline.
    /// `NostrAuthModal` cancels its login by dropping this future when the user leaves it, or when a
    /// logout or session removal cancels it under the provider's modal. That closes the socket and
    /// clears the approval link. A signer may already have consumed a one-time secret, so a retry
    /// can need a new URI.
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features, when connection fails,
    /// or when given a `nostrconnect://` URI (client-initiated pairing is not
    /// yet supported). Returns [`NostrAuthError::BunkerAuthRequired`] when the signer asks for
    /// approval and no modal is mounted to show the link when the timeout fires.
    pub async fn connect(uri: &str, timeout_secs: u32) -> Result<Self, NostrAuthError> {
        imp::connect(uri, timeout_secs).await
    }

    /// Reconnect a previously-authorized session without the bunker's original pairing secret.
    ///
    /// `client_secret_hex` is the hex secret of the *local* NIP-46 pairing keypair generated
    /// by the original [`BunkerSession::connect`] call — never the user's Nostr identity key,
    /// never the bunker's one-time secret. Per NIP-46, that secret is single-use and the remote
    /// signer is expected to already recognize this client's public key from the original
    /// pairing, so only `get_public_key` is sent. Behaviour on a revoked client varies by signer:
    /// one that answers `get_public_key` to anyone restores it as authenticated, and it fails at
    /// the first signature. A signer that refuses makes this call fail, and the caller should fall
    /// back to prompting the user to reconnect from scratch.
    pub(crate) async fn reconnect(
        uri_without_secret: &str,
        timeout_secs: u32,
        client_secret_hex: &str,
    ) -> Result<Self, NostrAuthError> {
        imp::reconnect(uri_without_secret, timeout_secs, client_secret_hex).await
    }

    /// Persisted so [`BunkerSession::reconnect`] can restore the client the bunker already
    /// authorized. This is not the user's Nostr secret key, but it is a live credential.
    pub(crate) fn client_secret_hex(&self) -> String {
        self.client_keys.secret_key().to_secret_hex()
    }

    #[cfg_attr(
        feature = "ssr",
        expect(clippy::missing_const_for_fn, reason = "only the server stub is const")
    )]
    pub(crate) fn close(&self) {
        imp::close(self);
    }

    /// Send a NIP-46 `sign_event` request to the remote signer.
    ///
    /// Reuses the persistent WebSocket if it is open; reconnects automatically if not, unless the
    /// session was closed.
    ///
    /// A lost socket ends the request with [`NostrAuthError::BunkerConnectionFailed`], including
    /// one waiting for approval, which then needs a retry, as soon as the browser reports the
    /// close. A relay's close frame with TCP held open can wait for the browser's grace period or a
    /// new request, bounded by the request's deadline. A pending request with no
    /// approval link can fail the same way once another request on the socket has timed out and a
    /// new one arrives, because the new one reconnects.
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when signing fails. Returns
    /// [`NostrAuthError::BunkerAuthRequired`] when the signer asks for approval and no modal is
    /// mounted to show the link, and [`NostrAuthError::BunkerSessionClosed`] once the session was
    /// closed. The request and the returned event follow the contract on
    /// [`crate::AuthResult::sign_event`]: a returned event from another key is
    /// [`NostrAuthError::SignerKeyMismatch`], and any other refusal is
    /// [`NostrAuthError::SigningFailed`] or [`NostrAuthError::Serialization`].
    pub async fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        imp::sign_event(self, event_json).await
    }

    /// NIP-44 encrypt via the remote signer (NIP-46 `nip44_encrypt` method).
    ///
    /// A lost socket ends the request the same way as on [`sign_event`](Self::sign_event).
    ///
    /// Before the first call on a session that has not signed anything, the signer is asked to sign
    /// a short check event that is never published; a signer that cannot sign it fails the call
    /// with `EncryptionFailed`.
    ///
    /// # Errors
    ///
    /// [`NostrAuthError::InvalidPublicKey`] when `peer` is not on the curve, before anything is sent
    /// and also on a closed session. [`NostrAuthError::EncryptionFailed`] when the signer refuses or
    /// answers with something malformed; a refusal's text is the signer's, sanitized and capped.
    /// [`NostrAuthError::BunkerSessionClosed`] once closed, for a valid peer.
    /// [`NostrAuthError::BunkerAuthRequired`] when the signer asks for approval and no modal is
    /// mounted to show the link, and [`NostrAuthError::BunkerTimeout`] or
    /// [`NostrAuthError::BunkerConnectionFailed`] for a transport failure. With SSR features a valid
    /// `peer` gets [`NostrAuthError::EncryptionUnavailable`].
    pub async fn nip44_encrypt(
        &self,
        peer: &PublicKey,
        plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        super::check_on_curve(peer)?;
        imp::nip44_encrypt(self, peer, plaintext).await
    }

    /// NIP-44 decrypt via the remote signer (NIP-46 `nip44_decrypt` method).
    ///
    /// A lost socket ends the request the same way as on [`sign_event`](Self::sign_event).
    ///
    /// Before the first call on a session that has not signed anything, the signer is asked to sign
    /// a short check event that is never published; a signer that cannot sign it fails the call
    /// with `EncryptionFailed`.
    ///
    /// # Errors
    ///
    /// The same as [`nip44_encrypt`](Self::nip44_encrypt).
    pub async fn nip44_decrypt(
        &self,
        peer: &PublicKey,
        ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        super::check_on_curve(peer)?;
        imp::nip44_decrypt(self, peer, ciphertext).await
    }
}

impl BunkerSession {
    /// Built from the private fields, so a reassigned `bunker_uri` cannot persist a secret.
    #[cfg_attr(
        feature = "ssr",
        expect(clippy::missing_const_for_fn, reason = "only the server stub is const")
    )]
    pub(crate) fn uri_to_persist(&self) -> Option<String> {
        imp::uri_to_persist(self)
    }
}

/// The approval link on show, if any. A tracked read, so modal closures react.
#[cfg_attr(
    feature = "ssr",
    expect(clippy::missing_const_for_fn, reason = "only the server stub is const")
)]
pub fn current_auth_url() -> Option<String> {
    imp::current_auth_url()
}

/// The host of an approval link, as the user should read it (punycode for an IDN).
#[cfg_attr(
    feature = "ssr",
    expect(clippy::missing_const_for_fn, reason = "only the server stub is const")
)]
pub fn auth_url_host(url: &str) -> Option<String> {
    imp::auth_url_host(url)
}

/// Stop showing the current approval link. Its request continues until its deadline.
#[cfg_attr(
    feature = "ssr",
    expect(clippy::missing_const_for_fn, reason = "only the server stub is const")
)]
pub fn dismiss_auth_prompt() {
    imp::dismiss_auth_prompt();
}

#[cfg_attr(
    feature = "ssr",
    expect(clippy::missing_const_for_fn, reason = "only the server stub is const")
)]
pub fn register_auth_presenter() {
    imp::register_auth_presenter();
}

#[cfg_attr(
    feature = "ssr",
    expect(clippy::missing_const_for_fn, reason = "only the server stub is const")
)]
pub fn unregister_auth_presenter() {
    imp::unregister_auth_presenter();
}

#[cfg(not(feature = "ssr"))]
mod imp {
    use core::cell::{Cell, RefCell};
    use core::fmt::Write;
    use js_sys::{Array, Promise};
    use leptos::prelude::{ArcRwSignal, Read, Update, WithUntracked};
    use nostr::event::{Kind, Tag, UnsignedEvent};
    use nostr::key::{Keys, PublicKey, SecretKey};
    use nostr::nips::nip46::{NostrConnectRequest, ResponseResult};
    use nostr::types::RelayUrl;
    use send_wrapper::SendWrapper;
    use std::rc::Rc;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;

    use super::BunkerSession;
    use crate::signers::browser::{
        RpcTimer, js_err_msg, make_rpc_promise, now_timestamp, random_bytes,
    };
    use crate::signers::event_contract::{checked_event, prepare};
    use crate::signers::nip46_protocol::{
        AUTH_URL_TIMEOUT_SECS, AttemptLog, BunkerTarget, DeadlineAction, Effect, Handshake,
        HttpsUrl, Inflight, MAX_FRAME_CHARS, Peer, PromptList, RECONNECT_CANCELLED, ReconnectGate,
        ReconnectOutcome, ReconnectWaker, RpcFailure, connect_request, connect_result, event_frame,
        needs_connect, nip44_result, parse_bunker_uri, persisted_uri, public_key_result,
        request_event, request_message, rotate_to_front, signed_event_result, subscribe_frame,
    };
    use crate::types::NostrAuthError;

    thread_local! {
        /// Global because challenges often arrive at `sign_event` and at restore, with the modal
        /// closed, and threading a handle there would change public signatures. A tab is one
        /// thread and one user.
        static PROMPTS: ArcRwSignal<PromptList> = ArcRwSignal::new(PromptList::default());
        static PRESENTERS: Cell<u32> = const { Cell::new(0) };
    }

    pub(super) fn current_auth_url() -> Option<String> {
        PROMPTS.with(|prompts| prompts.read().current().map(str::to_owned))
    }

    pub(super) fn auth_url_host(url: &str) -> Option<String> {
        crate::signers::nip46_protocol::auth_url_host(url)
    }

    pub(super) fn uri_to_persist(session: &BunkerSession) -> Option<String> {
        persisted_uri(&session.remote_pubkey, &session.relays).ok()
    }

    pub(super) fn dismiss_auth_prompt() {
        PROMPTS.with(|prompts| prompts.update(PromptList::remove_current));
    }

    pub(super) fn register_auth_presenter() {
        PRESENTERS.with(|count| count.set(count.get().saturating_add(1)));
    }

    pub(super) fn unregister_auth_presenter() {
        PRESENTERS.with(|count| count.set(count.get().saturating_sub(1)));
    }

    fn presenter_mounted() -> bool {
        PRESENTERS.with(Cell::get) > 0
    }

    pub(super) fn show_prompt(id: String, url: HttpsUrl) {
        PROMPTS.with(|prompts| prompts.update(|list| list.upsert(id, url)));
    }

    fn remove_prompt(id: &str) {
        PROMPTS.with(|prompts| {
            if prompts.with_untracked(|list| list.has(id)) {
                prompts.update(|list| {
                    list.remove(id);
                });
            }
        });
    }

    type Outcome = Result<ResponseResult, RpcFailure>;

    /// Wakes a waiting call. The typed outcome goes through the slot, so the promise is only a
    /// wake-up and no error text has to survive a trip through JS.
    pub(super) struct Waker<T> {
        slot: Rc<RefCell<Option<T>>>,
        resolve: js_sys::Function,
    }

    impl<T> Waker<T> {
        fn wake(self, outcome: T) {
            *self.slot.borrow_mut() = Some(outcome);
            let _ = self.resolve.call0(&JsValue::UNDEFINED);
        }
    }

    impl ReconnectWaker for Waker<ReconnectOutcome> {
        fn wake(self, outcome: ReconnectOutcome) {
            Self::wake(self, outcome);
        }
    }

    fn wake_pair<T>() -> (Promise, Rc<RefCell<Option<T>>>, Waker<T>) {
        let slot = Rc::new(RefCell::new(None));
        let (woken, resolve, _) = make_rpc_promise();
        let waker = Waker {
            slot: Rc::clone(&slot),
            resolve,
        };
        (woken, slot, waker)
    }

    pub(super) type RpcWaker = Waker<Outcome>;

    pub(super) type InflightSlot = Rc<RefCell<Inflight<RpcWaker>>>;

    /// A socket's event closures, owned here because the socket only borrows them.
    #[expect(dead_code, reason = "held to keep the closures alive, never read")]
    pub(super) struct SocketHandlers {
        on_message: Closure<dyn FnMut(web_sys::MessageEvent)>,
        on_close: Closure<dyn FnMut(web_sys::Event)>,
    }

    pub(super) type ConnectLock = Rc<ReconnectGate<Waker<ReconnectOutcome>>>;

    /// A socket handler must not capture this: the socket would keep it alive through the closure
    /// it owns, and its last-owner cleanup would never run.
    #[derive(Default)]
    pub(super) struct Connection {
        ws: RefCell<Option<web_sys::WebSocket>>,
        /// Replacing them on reconnect drops the previous closures' `client_keys` clones instead
        /// of leaking them.
        handlers: RefCell<Option<SocketHandlers>>,
        inflight: InflightSlot,
        connect_lock: ConnectLock,
        /// Set by the first `sign_event` that passes `checked_event`; never cleared.
        proven: Cell<bool>,
        proof_lock: ConnectLock,
        /// Set once by `close`, and never cleared.
        pub(super) closed: Cell<bool>,
        /// The attempt `do_reconnect` is opening. It is not in `ws` and has no request entries,
        /// so `close` reaches it only through this. A dropped future leaves a stale entry, and
        /// closing that again is harmless.
        opening: RefCell<Option<OpeningSocket>>,
    }

    struct OpeningSocket {
        ws: web_sys::WebSocket,
        wake: js_sys::Function,
    }

    fn closed_error() -> NostrAuthError {
        RpcFailure::SessionClosed.into_connect_error()
    }

    impl Connection {
        /// Must stay free of signal access: `Drop` can run while `set_auth` holds its write guard.
        /// The failure pass goes before `retire_socket`, so waiters get the closed error rather
        /// than a lost socket. Handlers stay alive until `Connection` drops; every socket's hooks
        /// are already cleared by then.
        pub(super) fn close(&self) {
            self.closed.set(true);
            let effects = self.inflight.borrow_mut().fail_session_closed();
            run_effects(effects, None);
            let current = self.ws.borrow().clone();
            if let Some(ws) = current {
                self.retire_socket(&ws, false);
            }
            let opening = self.opening.borrow_mut().take();
            if let Some(OpeningSocket { ws, wake }) = opening {
                close_socket(&ws);
                let _ = wake.call0(&JsValue::UNDEFINED);
            }
        }

        /// Stop using `ws` and fail what is in flight on it. A relay's close frame leaves a socket
        /// `CLOSING` with no close event yet, and closing it here clears `onclose`, so its entries
        /// must fail now or they wait out their deadlines.
        fn retire_socket(&self, ws: &web_sys::WebSocket, replaced: bool) {
            let current = self.ws.borrow().as_ref() == Some(ws);
            if current {
                *self.ws.borrow_mut() = None;
            }
            close_socket(ws);
            let effects = if replaced {
                self.inflight.borrow_mut().fail_socket_replaced()
            } else {
                self.inflight.borrow_mut().fail_socket_lost()
            };
            run_effects(effects, None);
        }
    }

    impl Drop for Connection {
        fn drop(&mut self) {
            self.close();
        }
    }

    /// Removes a request from `Inflight` on every exit from `send_on`, including a dropped future,
    /// which runs no exit code.
    pub(super) struct RequestGuard<W> {
        inflight: Rc<RefCell<Inflight<W>>>,
        id: String,
    }

    impl<W> RequestGuard<W> {
        pub(super) const fn new(inflight: Rc<RefCell<Inflight<W>>>, id: String) -> Self {
            Self { inflight, id }
        }
    }

    impl<W> Drop for RequestGuard<W> {
        fn drop(&mut self) {
            self.inflight.borrow_mut().remove(&self.id);
            remove_prompt(&self.id);
        }
    }

    /// Owns a socket being opened or handshaked. It is not in `BunkerSession::ws` yet, so nothing
    /// else could close it if the caller drops the future.
    struct AttemptGuard {
        ws: web_sys::WebSocket,
        armed: bool,
    }

    impl AttemptGuard {
        fn disarm(mut self) -> web_sys::WebSocket {
            self.armed = false;
            self.ws.clone()
        }
    }

    impl Drop for AttemptGuard {
        fn drop(&mut self) {
            if self.armed {
                close_socket(&self.ws);
            }
        }
    }

    /// The single socket cleanup. Handlers go first, because the closures they point at can be
    /// freed while the socket is still closing.
    ///
    /// No close event reaches anyone after this, so the caller must have failed, or be about to
    /// fail, what is in flight on this socket.
    fn close_socket(ws: &web_sys::WebSocket) {
        ws.set_onmessage(None);
        ws.set_onopen(None);
        ws.set_onerror(None);
        ws.set_onclose(None);
        let _ = ws.close();
    }

    /// Run what a relay frame or a lost socket caused, after the `Inflight` borrow has ended.
    fn run_effects(effects: Vec<Effect<RpcWaker>>, ws: Option<&web_sys::WebSocket>) {
        for effect in effects {
            match effect {
                Effect::Settle { waker, outcome } => waker.wake(outcome),
                Effect::Prompt { request_id, url } => show_prompt(request_id, url),
                Effect::CloseSocket => {
                    if let Some(ws) = ws {
                        close_socket(ws);
                    }
                }
            }
        }
    }

    pub(super) async fn connect(
        uri: &str,
        timeout_secs: u32,
    ) -> Result<BunkerSession, NostrAuthError> {
        let target = parse_bunker_uri(uri)?;
        let handshake = Handshake::Pair {
            secret: target.secret.clone(),
        };
        BunkerSession::connect_with_keys(target, timeout_secs, Keys::generate(), handshake).await
    }

    pub(super) fn close(session: &BunkerSession) {
        session.conn.close();
    }

    pub(super) async fn reconnect(
        uri_without_secret: &str,
        timeout_secs: u32,
        client_secret_hex: &str,
    ) -> Result<BunkerSession, NostrAuthError> {
        let secret_key = SecretKey::from_hex(client_secret_hex)
            .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;
        let target = parse_bunker_uri(uri_without_secret)?;
        BunkerSession::connect_with_keys(
            target,
            timeout_secs,
            Keys::new(secret_key),
            Handshake::Restore,
        )
        .await
    }

    pub(super) async fn sign_event(
        session: &BunkerSession,
        event_json: &str,
    ) -> Result<String, NostrAuthError> {
        let request = prepare(event_json, session.public_key)?;
        let returned = session
            .send_rpc(&NostrConnectRequest::SignEvent(request.clone()))
            .await
            .and_then(signed_event_result)
            .map_err(RpcFailure::into_signing_error)?;
        let checked = checked_event(&request, session.public_key, &returned)?;
        session.conn.proven.set(true);
        Ok(checked)
    }

    const PROOF_KIND: u16 = 29_421;
    const PROOF_FAILED: &str = "the remote signer did not prove it holds this account's key";

    /// A public key is public, so `get_public_key` proves nothing; NIP-44 waits for a checked
    /// signature. Concurrent callers share one challenge, so a signer that prompts per request asks
    /// once.
    async fn ensure_proven(session: &BunkerSession) -> Result<(), NostrAuthError> {
        if session.conn.closed.get() {
            return Err(closed_error());
        }
        for _ in 0..3 {
            if session.conn.proven.get() {
                return Ok(());
            }
            let (woken, slot, waker) = wake_pair();
            if let Some(lead) = session.conn.proof_lock.join(waker) {
                let result = prove(session).await;
                lead.finish(result.clone());
                return result;
            }
            let _ = JsFuture::from(woken).await;
            let outcome = slot.borrow_mut().take();
            match outcome {
                Some(Err(NostrAuthError::BunkerConnectionFailed(m)))
                    if m == RECONNECT_CANCELLED => {}
                Some(outcome) => return outcome,
                None => {}
            }
        }
        Err(NostrAuthError::EncryptionFailed(PROOF_FAILED.into()))
    }

    async fn prove(session: &BunkerSession) -> Result<(), NostrAuthError> {
        let challenge = UnsignedEvent::new(
            session.public_key,
            now_timestamp(),
            Kind::Custom(PROOF_KIND),
            [Tag::custom("challenge", [hex_of(&random_bytes(32))])],
            "leptos-nostr-auth: confirm this signer holds the key",
        );
        match sign_event(session, &challenge.as_json()).await {
            Ok(_) => Ok(()),
            Err(NostrAuthError::SigningFailed(why)) => Err(NostrAuthError::EncryptionFailed(
                format!("{PROOF_FAILED}: {why}"),
            )),
            Err(NostrAuthError::SignerKeyMismatch) => {
                Err(NostrAuthError::EncryptionFailed(PROOF_FAILED.into()))
            }
            Err(other) => Err(other),
        }
    }

    pub(super) async fn nip44_encrypt(
        session: &BunkerSession,
        peer: &PublicKey,
        plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        ensure_proven(session).await?;
        let request = NostrConnectRequest::Nip44Encrypt {
            public_key: *peer,
            text: plaintext.to_owned(),
        };
        session
            .send_rpc(&request)
            .await
            .and_then(nip44_result)
            .map_err(RpcFailure::into_encryption_error)
    }

    pub(super) async fn nip44_decrypt(
        session: &BunkerSession,
        peer: &PublicKey,
        ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        ensure_proven(session).await?;
        let request = NostrConnectRequest::Nip44Decrypt {
            public_key: *peer,
            ciphertext: ciphertext.to_owned(),
        };
        session
            .send_rpc(&request)
            .await
            .and_then(nip44_result)
            .map_err(RpcFailure::into_encryption_error)
    }

    impl BunkerSession {
        async fn connect_with_keys(
            target: BunkerTarget,
            timeout_secs: u32,
            client_keys: Keys,
            handshake: Handshake,
        ) -> Result<Self, NostrAuthError> {
            let BunkerTarget {
                remote,
                mut relays,
                secret: _,
            } = target;
            // `public_key` is the remote signer's only until `get_public_key` answers. This value
            // never leaves this function.
            let transport = Self {
                public_key: remote,
                bunker_uri: String::new(),
                timeout_secs,
                client_keys,
                remote_pubkey: remote,
                relays: relays.clone(),
                conn: SendWrapper::new(Rc::default()),
            };
            let mut paired = false;
            let mut failures = AttemptLog::default();
            for relay in &transport.relays {
                match transport.handshake_on(relay, &handshake, &mut paired).await {
                    Ok((public_key, ws)) => {
                        *transport.conn.ws.borrow_mut() = Some(ws);
                        rotate_to_front(&mut relays, relay);
                        let bunker_uri = persisted_uri(&remote, &relays)?;
                        return Ok(Self {
                            public_key,
                            bunker_uri,
                            relays,
                            ..transport
                        });
                    }
                    Err(failure) => {
                        if let Some(stop) = failures.record(failure) {
                            return Err(stop.into_connect_error());
                        }
                    }
                }
            }
            Err(failures.finish().into_connect_error())
        }

        /// Its socket closes on any exit but success.
        async fn handshake_on(
            &self,
            relay: &RelayUrl,
            handshake: &Handshake,
            paired: &mut bool,
        ) -> Result<(PublicKey, web_sys::WebSocket), RpcFailure> {
            let attempt = self.open_relay(relay).await.map_err(RpcFailure::Socket)?;
            if needs_connect(handshake, *paired) {
                let request = connect_request(handshake, self.remote_pubkey);
                let secret = match handshake {
                    Handshake::Pair { secret } => secret.as_deref(),
                    Handshake::Restore => None,
                };
                connect_result(self.send_on(&attempt.ws, &request).await?, secret)?;
                *paired = true;
            }
            let public_key = public_key_result(
                self.send_on(&attempt.ws, &NostrConnectRequest::GetPublicKey)
                    .await?,
            )?;
            Ok((public_key, attempt.disarm()))
        }

        /// Concurrent callers serialize on `connect_lock`: only the first caller
        /// actually reconnects; subsequent callers wait for that attempt's outcome instead of each
        /// opening their own socket (which would orphan all but one in-flight RPC until timeout).
        /// A follower waits as long as the leader can take: one open per relay.
        async fn ensure_ws(&self) -> Result<web_sys::WebSocket, NostrAuthError> {
            if self.conn.closed.get() {
                return Err(closed_error());
            }
            let current = self.conn.ws.borrow().clone();
            let must_reconnect = self.conn.inflight.borrow().must_reconnect();
            if let Some(ws) = current
                && ws.ready_state() == web_sys::WebSocket::OPEN
                && !must_reconnect
            {
                return Ok(ws);
            }

            let rounds = u32::try_from(self.relays.len()).unwrap_or(u32::MAX);
            let wait_secs = self.timeout_secs.saturating_mul(rounds).saturating_add(1);
            for _ in 0..3 {
                let (woken, slot, waker) = wake_pair();
                if let Some(lead) = self.conn.connect_lock.join(waker) {
                    let result = self.do_reconnect().await;
                    lead.finish(result.as_ref().map(|_| ()).map_err(Clone::clone));
                    return result;
                }

                let timer = RpcTimer::start(wait_secs);
                let race = Promise::race(&Array::of2(&woken, timer.fired()));
                let _ = JsFuture::from(race).await;
                let outcome = slot.borrow_mut().take();
                if self.conn.closed.get() {
                    return Err(closed_error());
                }
                match outcome {
                    None => return Err(NostrAuthError::BunkerTimeout),
                    Some(Err(NostrAuthError::BunkerConnectionFailed(m)))
                        if m == RECONNECT_CANCELLED => {}
                    Some(Err(e)) => return Err(e),
                    Some(Ok(())) => {
                        return self.conn.ws.borrow().as_ref().cloned().ok_or_else(|| {
                            NostrAuthError::BunkerConnectionFailed("reconnect failed".into())
                        });
                    }
                }
            }
            Err(NostrAuthError::BunkerConnectionFailed(
                RECONNECT_CANCELLED.into(),
            ))
        }

        /// Only called from `ensure_ws`, which serializes concurrent callers.
        async fn do_reconnect(&self) -> Result<web_sys::WebSocket, NostrAuthError> {
            let old_ws = self.conn.ws.borrow().clone();
            if let Some(old_ws) = old_ws {
                self.conn
                    .retire_socket(&old_ws, old_ws.ready_state() == web_sys::WebSocket::OPEN);
            }
            let mut last = NostrAuthError::BunkerConnectionFailed("no relay to try".into());
            for relay in &self.relays {
                let opened = self.open_relay(relay).await;
                if self.conn.closed.get() {
                    return Err(closed_error());
                }
                match opened {
                    Ok(attempt) => {
                        let ws = attempt.disarm();
                        *self.conn.ws.borrow_mut() = Some(ws.clone());
                        return Ok(ws);
                    }
                    Err(e) => last = e,
                }
            }
            Err(last)
        }

        async fn open_relay(&self, relay: &RelayUrl) -> Result<AttemptGuard, NostrAuthError> {
            let ws = web_sys::WebSocket::new(relay.as_str()).map_err(|e| {
                NostrAuthError::BunkerConnectionFailed(format!("WebSocket: {}", js_err_msg(&e)))
            })?;
            let attempt = AttemptGuard {
                ws: ws.clone(),
                armed: true,
            };
            ws.set_binary_type(web_sys::BinaryType::Arraybuffer);
            self.conn.inflight.borrow_mut().reset_socket();
            self.install_handlers(&ws);

            let (open_promise, open_resolve, open_reject) = make_rpc_promise();
            let open_wake = open_resolve.clone();
            let on_open = Closure::<dyn FnMut(_)>::new(move |_: web_sys::Event| {
                let _ = open_resolve.call1(&JsValue::UNDEFINED, &JsValue::UNDEFINED);
            });
            let on_error_open = Closure::<dyn FnMut(_)>::new(move |_: web_sys::Event| {
                let _ = open_reject.call1(
                    &JsValue::UNDEFINED,
                    &JsValue::from_str("WebSocket error during connection"),
                );
            });
            *self.conn.opening.borrow_mut() = Some(OpeningSocket {
                ws: ws.clone(),
                wake: open_wake,
            });
            ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
            ws.set_onerror(Some(on_error_open.as_ref().unchecked_ref()));

            let opened = {
                let timer = RpcTimer::start(self.timeout_secs);
                let race = Promise::race(&Array::of2(&open_promise, timer.fired()));
                JsFuture::from(race).await
            };

            *self.conn.opening.borrow_mut() = None;
            ws.set_onopen(None);
            ws.set_onerror(None);

            if let Err(e) = opened {
                return Err(NostrAuthError::BunkerConnectionFailed(js_err_msg(&e)));
            }
            if ws.ready_state() != web_sys::WebSocket::OPEN {
                return Err(NostrAuthError::BunkerTimeout);
            }

            ws.send_with_str(&subscribe_frame(self.client_keys.public_key()))
                .map_err(|e| NostrAuthError::BunkerConnectionFailed(js_err_msg(&e)))?;
            Ok(attempt)
        }

        fn install_handlers(&self, ws: &web_sys::WebSocket) {
            let inflight = Rc::clone(&self.conn.inflight);
            let peer = Peer {
                client: self.client_keys.clone(),
                remote: self.remote_pubkey,
            };
            let on_message = Closure::<dyn FnMut(_)>::new(move |e: web_sys::MessageEvent| {
                let raw = e.data();
                let Some(text) = raw.dyn_ref::<js_sys::JsString>() else {
                    return;
                };
                if text.length() as usize > MAX_FRAME_CHARS {
                    return;
                }
                let Some(data) = text.as_string() else {
                    return;
                };
                let effects = inflight.borrow_mut().on_frame(&data, &peer);
                let target = e
                    .target()
                    .and_then(|t| t.dyn_into::<web_sys::WebSocket>().ok());
                run_effects(effects, target.as_ref());
            });
            let inflight = Rc::clone(&self.conn.inflight);
            let on_close = Closure::<dyn FnMut(_)>::new(move |_: web_sys::Event| {
                let effects = inflight.borrow_mut().fail_socket_lost();
                run_effects(effects, None);
            });
            ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
            ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));
            *self.conn.handlers.borrow_mut() = Some(SocketHandlers {
                on_message,
                on_close,
            });
        }

        async fn send_rpc(&self, request: &NostrConnectRequest) -> Outcome {
            let ws = self.ensure_ws().await.map_err(RpcFailure::Socket)?;
            let result = self.send_on(&ws, request).await;
            let current = self.conn.ws.borrow().as_ref() == Some(&ws);
            if !current {
                return result;
            }
            let tear_down = self
                .conn
                .inflight
                .borrow_mut()
                .note_settled(result.as_ref().err());
            if tear_down {
                self.conn.retire_socket(&ws, false);
            }
            result
        }

        /// The one RPC body. Takes the socket so a handshake cannot finish on a different relay
        /// from the one it opened, and cannot reach `ensure_ws`.
        async fn send_on(&self, ws: &web_sys::WebSocket, request: &NostrConnectRequest) -> Outcome {
            if ws.ready_state() != web_sys::WebSocket::OPEN {
                return Err(RpcFailure::Socket(NostrAuthError::BunkerConnectionFailed(
                    "relay socket is not open".into(),
                )));
            }
            let id = generate_request_id();
            let message = request_message(id.clone(), request);
            let event = request_event(
                &self.client_keys,
                self.remote_pubkey,
                &message,
                now_timestamp(),
            )
            .ok_or(RpcFailure::Build)?;

            let (woken, slot, waker): (_, _, RpcWaker) = wake_pair();
            self.conn
                .inflight
                .borrow_mut()
                .insert(id.clone(), request.method(), event.id, waker);
            let _guard = RequestGuard::new(Rc::clone(&self.conn.inflight), id.clone());

            ws.send_with_str(&event_frame(&event)).map_err(|e| {
                RpcFailure::Socket(NostrAuthError::BunkerConnectionFailed(js_err_msg(&e)))
            })?;

            let mut wait_secs = self.timeout_secs;
            loop {
                let timer = RpcTimer::start(wait_secs);
                let race = Promise::race(&Array::of2(&woken, timer.fired()));
                let _ = JsFuture::from(race).await;
                if let Some(outcome) = slot.borrow_mut().take() {
                    return outcome;
                }
                let mut inflight = self.conn.inflight.borrow_mut();
                match inflight.on_deadline(&id, presenter_mounted()) {
                    DeadlineAction::Extend => wait_secs = AUTH_URL_TIMEOUT_SECS,
                    DeadlineAction::Timeout { signer_answered } => {
                        return Err(inflight.timeout_failure(signer_answered));
                    }
                    DeadlineAction::AuthRequired => return Err(RpcFailure::AuthRequired),
                }
            }
        }
    }

    fn hex_of(bytes: &[u8]) -> String {
        bytes.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        })
    }

    fn generate_request_id() -> String {
        random_bytes(8).iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02X}");
            acc
        })
    }

    #[cfg(all(test, target_arch = "wasm32"))]
    #[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
    mod ws_tests {
        use super::*;
        use crate::signers::test_ws;
        use wasm_bindgen_test::wasm_bindgen_test;

        fn session_on(relays: &[&str]) -> BunkerSession {
            let client_keys = Keys::generate();
            BunkerSession {
                public_key: client_keys.public_key(),
                bunker_uri: String::new(),
                timeout_secs: 1,
                remote_pubkey: Keys::generate().public_key(),
                client_keys,
                relays: relays.iter().map(|r| RelayUrl::parse(r).unwrap()).collect(),
                conn: SendWrapper::new(Rc::default()),
            }
        }

        #[wasm_bindgen_test]
        async fn follower_outlives_a_slow_first_relay() {
            test_ws::install();
            let s = session_on(&["wss://hang.example", "wss://ok.example"]);
            let (lead, follow) = futures::future::join(s.ensure_ws(), s.ensure_ws()).await;
            assert!(lead.is_ok(), "leader failed: {:?}", lead.err());
            assert!(follow.is_ok(), "follower failed: {:?}", follow.err());
        }

        #[wasm_bindgen_test]
        async fn follower_survives_a_cancelled_leader() {
            use futures::FutureExt as _;
            test_ws::install();
            let s = session_on(&["wss://ok.example"]);
            let mut lead = Box::pin(s.ensure_ws());
            let mut follow = Box::pin(s.ensure_ws());
            assert!((&mut lead).now_or_never().is_none());
            assert!((&mut follow).now_or_never().is_none());
            drop(lead);
            assert!(
                follow.await.is_ok(),
                "follower failed after its leader was dropped"
            );
        }
    }
}

#[cfg(feature = "ssr")]
mod imp {
    use nostr::key::PublicKey;

    use super::BunkerSession;
    use crate::signers::NOT_ON_SERVER;
    use crate::types::NostrAuthError;

    pub(super) async fn connect(
        _uri: &str,
        _timeout_secs: u32,
    ) -> Result<BunkerSession, NostrAuthError> {
        Err(NostrAuthError::BunkerConnectionFailed(NOT_ON_SERVER.into()))
    }

    pub(super) async fn reconnect(
        _uri_without_secret: &str,
        _timeout_secs: u32,
        _client_secret_hex: &str,
    ) -> Result<BunkerSession, NostrAuthError> {
        Err(NostrAuthError::BunkerConnectionFailed(NOT_ON_SERVER.into()))
    }

    pub(super) async fn sign_event(
        _session: &BunkerSession,
        _event_json: &str,
    ) -> Result<String, NostrAuthError> {
        Err(NostrAuthError::SigningFailed(NOT_ON_SERVER.into()))
    }

    pub(super) async fn nip44_encrypt(
        _session: &BunkerSession,
        _peer: &PublicKey,
        _plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        Err(NostrAuthError::EncryptionUnavailable)
    }

    pub(super) async fn nip44_decrypt(
        _session: &BunkerSession,
        _peer: &PublicKey,
        _ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        Err(NostrAuthError::EncryptionUnavailable)
    }

    pub(super) const fn close(_session: &BunkerSession) {}

    /// No state may cross requests.
    pub(super) const fn current_auth_url() -> Option<String> {
        None
    }

    pub(super) const fn auth_url_host(_url: &str) -> Option<String> {
        None
    }

    pub(super) const fn uri_to_persist(_session: &BunkerSession) -> Option<String> {
        None
    }

    pub(super) const fn dismiss_auth_prompt() {}

    pub(super) const fn register_auth_presenter() {}

    pub(super) const fn unregister_auth_presenter() {}
}

#[cfg(test)]
#[cfg(not(feature = "ssr"))]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod tests {
    use super::*;
    use crate::signers::nip46_protocol::{Inflight, parse_auth_url};
    use core::cell::RefCell;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use nostr::event::EventId;
    use nostr::nips::nip46::NostrConnectMethod;
    use std::rc::Rc;

    fn session() -> BunkerSession {
        let client_keys = Keys::generate();
        BunkerSession {
            public_key: client_keys.public_key(),
            bunker_uri: String::new(),
            timeout_secs: 1,
            remote_pubkey: client_keys.public_key(),
            client_keys,
            relays: Vec::new(),
            conn: send_wrapper::SendWrapper::new(Rc::default()),
        }
    }

    #[test]
    fn clones_share_one_connection() {
        let a = session();
        let b = a.clone();
        assert!(Rc::ptr_eq(&a.conn, &b.conn));
        drop(b);
        assert!(!a.conn.closed.get());
    }

    // Reaching `web_sys` would panic natively, so this also pins the check's place at the top.
    #[test]
    fn closed_session_refuses_before_any_socket() {
        let s = session();
        s.conn.close();
        let event = r#"{"kind":1,"content":"x","tags":[],"created_at":1700000000}"#;
        let polled = pin!(s.sign_event(event)).poll(&mut Context::from_waker(Waker::noop()));
        assert!(matches!(
            polled,
            Poll::Ready(Err(NostrAuthError::BunkerSessionClosed))
        ));
    }

    #[test]
    fn closed_session_through_traits() {
        use crate::signers::signer_traits::tests::{ready, unsigned};
        use core::error::Error as _;
        use nostr::event::{AsyncSignEvent, FinalizeEventAsync};
        use nostr::key::AsyncGetPublicKey;
        let s = session();
        let pk = s.public_key;
        s.conn.close();
        let auth = crate::types::AuthResult::Bunker(Box::new(s));
        let direct = ready(auth.sign_event_async(unsigned(pk)));
        assert!(matches!(direct, Err(NostrAuthError::BunkerSessionClosed)));
        let wrapped = ready(unsigned(pk).finalize_async(&auth)).unwrap_err();
        let source = wrapped
            .source()
            .and_then(|e| e.downcast_ref::<NostrAuthError>());
        assert!(matches!(source, Some(NostrAuthError::BunkerSessionClosed)));
        #[cfg(not(target_arch = "wasm32"))]
        {
            use nostr::event::{EventBuilder, Kind};
            let built =
                ready(EventBuilder::new(Kind::TextNote, "hi").finalize_async(&auth)).unwrap_err();
            let source = built
                .source()
                .and_then(|e| e.downcast_ref::<NostrAuthError>());
            assert!(matches!(source, Some(NostrAuthError::BunkerSessionClosed)));
        }
        assert_eq!(ready(auth.get_public_key_async()).unwrap(), pk);
    }

    #[test]
    fn closed_session_nip44() {
        use crate::signers::signer_traits::tests::{off_curve, ready};
        use nostr::nips::nip44::AsyncNip44;
        let s = session();
        let peer = Keys::generate().public_key();
        let bad = off_curve();
        let auth = crate::types::AuthResult::Bunker(Box::new(s.clone()));
        let closed = |got: Result<String, NostrAuthError>| {
            assert!(matches!(got, Err(NostrAuthError::BunkerSessionClosed)));
        };
        let invalid = |got: Result<String, NostrAuthError>| {
            assert!(matches!(got, Err(NostrAuthError::InvalidPublicKey(_))));
        };
        invalid(ready(auth.nip44_encrypt(&bad, "x")));
        invalid(ready(auth.nip44_decrypt(&bad, "x")));
        s.conn.close();
        invalid(ready(auth.nip44_encrypt(&bad, "x")));
        invalid(ready(auth.nip44_decrypt(&bad, "x")));
        invalid(ready(s.nip44_encrypt(&bad, "x")));
        invalid(ready(s.nip44_decrypt(&bad, "x")));
        closed(ready(auth.nip44_encrypt(&peer, "x")));
        closed(ready(auth.nip44_decrypt(&peer, "x")));
        closed(ready(auth.nip44_encrypt_async(&peer, "x")));
        closed(ready(auth.nip44_decrypt_async(&peer, "x")));
        #[cfg(not(target_arch = "wasm32"))]
        {
            use core::error::Error as _;
            use nostr::event::FinalizeEvent;
            use nostr::nips::nip59::{GiftWrapBuilder, UnwrappedGift};
            let sender = Keys::generate();
            let wrap = GiftWrapBuilder::new(
                s.public_key,
                crate::signers::signer_traits::tests::unsigned(sender.public_key()),
            )
            .finalize(&sender)
            .unwrap();
            let err = ready(UnwrappedGift::from_gift_wrap_async(&auth, &wrap)).unwrap_err();
            assert_eq!(err.kind(), nostr::error::ErrorKind::Crypto);
            let source = err
                .source()
                .and_then(|e| e.downcast_ref::<NostrAuthError>());
            assert!(matches!(source, Some(NostrAuthError::BunkerSessionClosed)));
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn closed_session_through_trait_on_wasm() {
        use crate::signers::signer_traits::tests::unsigned;
        use nostr::event::AsyncSignEvent;
        use nostr::nips::nip44::AsyncNip44;
        let s = session();
        let pk = s.public_key;
        s.conn.close();
        let auth = crate::types::AuthResult::Bunker(Box::new(s));
        let r = auth.sign_event_async(unsigned(pk)).await;
        assert!(matches!(r, Err(NostrAuthError::BunkerSessionClosed)));
        let enc = auth.nip44_encrypt_async(&pk, "x").await;
        assert!(matches!(enc, Err(NostrAuthError::BunkerSessionClosed)));
        let dec = auth.nip44_decrypt_async(&pk, "x").await;
        assert!(matches!(dec, Err(NostrAuthError::BunkerSessionClosed)));
    }

    #[test]
    fn persisted_uri_never_carries_a_secret() {
        let mut s = session();
        s.relays = vec![RelayUrl::parse("wss://r.example").unwrap()];
        s.bunker_uri = format!(
            "bunker://{}?relay=wss%3A%2F%2Fr.example&secret=s3",
            s.remote_pubkey.to_hex()
        );
        let stored = crate::types::AuthResult::Bunker(Box::new(s))
            .to_persisted_session()
            .unwrap()
            .bunker_uri
            .unwrap();
        assert!(!stored.contains("secret"), "{stored}");
    }

    #[test]
    fn debug_redacts_bunker() {
        let mut s = session();
        s.bunker_uri = "bunker://abc?relay=wss%3A%2F%2Frelay.example&secret=TOPSECRET".to_owned();
        let pk = s.public_key.to_hex();
        let auth = crate::types::AuthResult::Bunker(Box::new(s));
        assert_eq!(
            format!("{auth:?}"),
            format!("Bunker {{ public_key: PublicKey({pk}) }}")
        );
        assert_eq!(
            format!("{auth:#?}"),
            format!("Bunker {{\n    public_key: PublicKey({pk}),\n}}")
        );
    }

    #[test]
    fn guard_drop_removes_entry_and_prompt() {
        let inflight = Rc::new(RefCell::new(Inflight::<()>::default()));
        inflight.borrow_mut().insert(
            "a".to_owned(),
            NostrConnectMethod::SignEvent,
            EventId::from_byte_array([1; 32]),
            (),
        );
        let guard = imp::RequestGuard::new(Rc::clone(&inflight), "a".to_owned());
        imp::show_prompt(
            "a".to_owned(),
            parse_auth_url("https://s.example/a").unwrap(),
        );
        assert!(inflight.borrow().contains("a"));
        assert_eq!(current_auth_url().as_deref(), Some("https://s.example/a"));
        drop(guard);
        assert!(!inflight.borrow().contains("a"));
        assert_eq!(current_auth_url(), None);
    }
}

#[cfg(test)]
#[cfg(feature = "ssr")]
pub(super) mod server_tests {
    use super::super::server_tests::{ready, text};
    use super::*;
    use crate::signers::signer_traits::tests::{UNAVAILABLE, off_curve};

    pub(in crate::signers) fn bunker() -> BunkerSession {
        let client_keys = Keys::generate();
        BunkerSession {
            public_key: client_keys.public_key(),
            bunker_uri: String::new(),
            timeout_secs: 1,
            remote_pubkey: client_keys.public_key(),
            client_keys,
            relays: Vec::new(),
        }
    }

    #[test]
    fn nip46_server_stubs() {
        let s = bunker();
        assert_eq!(
            text(ready(BunkerSession::connect("bunker://x", 1))),
            "Bunker connection failed: not available on server"
        );
        assert_eq!(
            text(ready(s.sign_event("{}"))),
            "Signing failed: not available on server"
        );
        let peer = Keys::generate().public_key();
        let bad = off_curve();
        assert_eq!(text(ready(s.nip44_encrypt(&peer, "b"))), UNAVAILABLE);
        assert_eq!(text(ready(s.nip44_decrypt(&peer, "b"))), UNAVAILABLE);
        let enc = ready(s.nip44_encrypt(&bad, "b"));
        assert!(matches!(enc, Err(NostrAuthError::InvalidPublicKey(_))));
        let dec = ready(s.nip44_decrypt(&bad, "b"));
        assert!(matches!(dec, Err(NostrAuthError::InvalidPublicKey(_))));
        let auth = crate::types::AuthResult::Bunker(Box::new(s));
        assert_eq!(text(ready(auth.nip44_encrypt(&peer, "b"))), UNAVAILABLE);
        assert_eq!(text(ready(auth.nip44_decrypt(&peer, "b"))), UNAVAILABLE);
    }

    #[test]
    fn close_does_nothing_on_server() {
        let s = bunker();
        s.close();
        let auth = crate::types::AuthResult::Bunker(Box::new(s));
        auth.close_session();
        assert_eq!(
            text(ready(auth.sign_event("{}"))),
            "Signing failed: not available on server"
        );
        let peer = Keys::generate().public_key();
        assert_eq!(text(ready(auth.nip44_encrypt(&peer, "b"))), UNAVAILABLE);
        assert_eq!(text(ready(auth.nip44_decrypt(&peer, "b"))), UNAVAILABLE);
    }

    #[test]
    fn bunker_reports_server_stub_through_trait() {
        use crate::signers::signer_traits::tests::{ready, unsigned};
        use nostr::event::AsyncSignEvent;
        let s = bunker();
        let pk = s.public_key;
        s.close();
        let auth = crate::types::AuthResult::Bunker(Box::new(s));
        assert_eq!(
            text(ready(auth.sign_event_async(unsigned(pk)))),
            "Signing failed: not available on server"
        );
    }

    #[test]
    fn prompt_facades_do_nothing_on_server() {
        register_auth_presenter();
        dismiss_auth_prompt();
        unregister_auth_presenter();
        assert_eq!(current_auth_url(), None);
    }
}
