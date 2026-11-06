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
    /// Timeout in seconds for RPC calls — stored from config at connect time
    timeout_secs: u32,
    /// Ephemeral client keypair — stays in memory
    client_keys: Keys,
    /// Remote signer's public key.
    remote_pubkey: PublicKey,
    /// Relays to try, working relay first.
    relays: Vec<RelayUrl>,
    /// The connection every clone shares.
    #[cfg(not(feature = "ssr"))]
    conn: send_wrapper::SendWrapper<std::rc::Rc<imp::Connection>>,
}

impl BunkerSession {
    /// Establish a NIP-46 connection from a `bunker://` URI (fresh login).
    ///
    /// Generates a new ephemeral local pairing keypair for this session. To restore a
    /// previously-authorized session without the bunker's one-time secret, the crate-internal
    /// `BunkerSession::reconnect` (used by session restore) is used instead.
    ///
    /// A URI may list up to five relays after duplicates are removed. If the signer sends an
    /// approval link, a mounted [`crate::modal::NostrAuthModal`] shows it, also while `open` is
    /// false, and that request waits one extra 300 s. A login with `n` relays can take up to
    /// `(2n+1) * timeout_secs + 600` seconds. A modal unmounted during that wait does not shorten
    /// it. A lost socket ends a wait at once, including one for approval, which then needs a retry.
    /// Closing the modal does not cancel a login: a dismissed login can still complete up to that
    /// bound later and call `on_auth`.
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
    ///
    /// Only called from `storage::restore_session`, which never runs on the server; the server
    /// stub exists so that caller compiles there.
    ///
    /// # Errors
    ///
    /// Returns an error when `client_secret_hex` is not a valid secret key, or when
    /// reconnection fails.
    pub(crate) async fn reconnect(
        uri_without_secret: &str,
        timeout_secs: u32,
        client_secret_hex: &str,
    ) -> Result<Self, NostrAuthError> {
        imp::reconnect(uri_without_secret, timeout_secs, client_secret_hex).await
    }

    /// Hex-encoded secret of this session's local NIP-46 pairing keypair.
    ///
    /// Persisted so [`BunkerSession::reconnect`] can restore the same client identity the
    /// bunker already authorized. This is **not** the user's Nostr secret key — see
    /// [`BunkerSession::reconnect`] docs for the exact risk model.
    pub(crate) fn client_secret_hex(&self) -> String {
        self.client_keys.secret_key().to_secret_hex()
    }

    /// Close this session for good, for every clone. See [`NostrAuthError::BunkerSessionClosed`].
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
    /// A lost socket ends the request at once with [`NostrAuthError::BunkerConnectionFailed`],
    /// including one waiting for approval, which then needs a retry. A pending request with no
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
    /// # Errors
    ///
    /// Returns an error when called with SSR features, when `recipient_hex` is not a public key,
    /// or when nip44 encryption fails. Returns [`NostrAuthError::BunkerAuthRequired`] when the
    /// signer asks for approval and no modal is mounted to show the link, and
    /// [`NostrAuthError::BunkerSessionClosed`] once the session was closed.
    pub async fn nip44_encrypt(
        &self,
        recipient_hex: &str,
        plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        imp::nip44_encrypt(self, recipient_hex, plaintext).await
    }

    /// NIP-44 decrypt via the remote signer (NIP-46 `nip44_decrypt` method).
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features, when `sender_hex` is not a public key, or
    /// when nip44 decryption fails. Returns [`NostrAuthError::BunkerAuthRequired`] when the signer
    /// asks for approval and no modal is mounted to show the link, and
    /// [`NostrAuthError::BunkerSessionClosed`] once the session was closed.
    pub async fn nip44_decrypt(
        &self,
        sender_hex: &str,
        ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        imp::nip44_decrypt(self, sender_hex, ciphertext).await
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

/// Stop showing the current approval link. Its request continues until its deadline.
#[cfg_attr(
    feature = "ssr",
    expect(clippy::missing_const_for_fn, reason = "only the server stub is const")
)]
pub fn dismiss_auth_prompt() {
    imp::dismiss_auth_prompt();
}

/// Record a mounted `NostrAuthModal`, which can show approval links.
#[cfg_attr(
    feature = "ssr",
    expect(clippy::missing_const_for_fn, reason = "only the server stub is const")
)]
pub fn register_auth_presenter() {
    imp::register_auth_presenter();
}

/// Record an unmounted `NostrAuthModal`.
#[cfg_attr(
    feature = "ssr",
    expect(clippy::missing_const_for_fn, reason = "only the server stub is const")
)]
pub fn unregister_auth_presenter() {
    imp::unregister_auth_presenter();
}

/// Browser implementation.
#[cfg(not(feature = "ssr"))]
mod imp {
    use core::cell::{Cell, RefCell};
    use core::fmt::Write;
    use js_sys::{Array, Promise};
    use leptos::prelude::{ArcRwSignal, Read, Update, WithUntracked};
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
        HttpsUrl, Inflight, Peer, PromptList, REQUEST_BUILD_FAILED, ReconnectGate,
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
        /// Mounted `NostrAuthModal`s.
        static PRESENTERS: Cell<u32> = const { Cell::new(0) };
    }

    /// See the facade.
    pub(super) fn current_auth_url() -> Option<String> {
        PROMPTS.with(|prompts| prompts.read().current().map(str::to_owned))
    }

    /// See the facade.
    pub(super) fn dismiss_auth_prompt() {
        PROMPTS.with(|prompts| prompts.update(PromptList::remove_current));
    }

    /// See the facade.
    pub(super) fn register_auth_presenter() {
        PRESENTERS.with(|count| count.set(count.get().saturating_add(1)));
    }

    /// See the facade.
    pub(super) fn unregister_auth_presenter() {
        PRESENTERS.with(|count| count.set(count.get().saturating_sub(1)));
    }

    /// Whether a mounted `NostrAuthModal` can show a link.
    fn presenter_mounted() -> bool {
        PRESENTERS.with(Cell::get) > 0
    }

    /// Show a request's approval link.
    pub(super) fn show_prompt(id: String, url: HttpsUrl) {
        PROMPTS.with(|prompts| prompts.update(|list| list.upsert(id, url)));
    }

    /// Remove a request's link, notifying readers only if it had one.
    fn remove_prompt(id: &str) {
        PROMPTS.with(|prompts| {
            if prompts.with_untracked(|list| list.has(id)) {
                prompts.update(|list| {
                    list.remove(id);
                });
            }
        });
    }

    /// How a settled request reaches the call awaiting it.
    type Outcome = Result<ResponseResult, RpcFailure>;

    /// Wakes a waiting call. The typed outcome goes through the slot, so the promise is only a
    /// wake-up and no error text has to survive a trip through JS.
    pub(super) struct Waker<T> {
        /// Read by the waiting call once woken.
        slot: Rc<RefCell<Option<T>>>,
        /// Resolves the promise the waiting call races.
        resolve: js_sys::Function,
    }

    impl<T> Waker<T> {
        /// Hand over the outcome and wake the waiting call.
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

    /// A promise to race, the slot to read once it resolves, and the waker that fills both.
    fn wake_pair<T>() -> (Promise, Rc<RefCell<Option<T>>>, Waker<T>) {
        let slot = Rc::new(RefCell::new(None));
        let (woken, resolve, _) = make_rpc_promise();
        let waker = Waker {
            slot: Rc::clone(&slot),
            resolve,
        };
        (woken, slot, waker)
    }

    /// Wakes `send_on`.
    pub(super) type RpcWaker = Waker<Outcome>;

    /// Requests awaiting a response.
    pub(super) type InflightSlot = Rc<RefCell<Inflight<RpcWaker>>>;

    /// A socket's event closures, owned here because the socket only borrows them.
    #[expect(dead_code, reason = "held to keep the closures alive, never read")]
    pub(super) struct SocketHandlers {
        /// `onmessage`.
        on_message: Closure<dyn FnMut(web_sys::MessageEvent)>,
        /// `onclose`.
        on_close: Closure<dyn FnMut(web_sys::Event)>,
    }

    /// Serializes reconnects.
    pub(super) type ConnectLock = Rc<ReconnectGate<Waker<ReconnectOutcome>>>;

    /// What every clone of a session shares.
    ///
    /// A socket handler must not capture this: the socket would keep it alive through the closure
    /// it owns, and its last-owner cleanup would never run.
    #[derive(Default)]
    pub(super) struct Connection {
        /// Persistent WebSocket: opened by the handshake, reopened by `ensure_ws` if lost.
        ws: RefCell<Option<web_sys::WebSocket>>,
        /// Current `onmessage` and `onclose` handlers. Replacing them on reconnect drops the
        /// previous closures' `client_keys` clones instead of leaking them.
        handlers: RefCell<Option<SocketHandlers>>,
        /// Requests awaiting a response.
        inflight: InflightSlot,
        /// Serializes reconnects: a concurrent caller waits for the running one's outcome, up to
        /// its own timeout, instead of racing a second WebSocket into existence. See `ensure_ws`.
        connect_lock: ConnectLock,
        /// Set once by `close`, and never cleared.
        pub(super) closed: Cell<bool>,
        /// The attempt `do_reconnect` is opening. It is not in `ws` and has no request entries,
        /// so `close` reaches it only through this. A dropped future leaves a stale entry, and
        /// closing that again is harmless.
        opening: RefCell<Option<OpeningSocket>>,
    }

    /// A socket still opening, and how to wake the call racing its open.
    struct OpeningSocket {
        /// The attempt's socket.
        ws: web_sys::WebSocket,
        /// Resolves the promise `open_relay` races.
        wake: js_sys::Function,
    }

    /// The error every call on a closed session returns.
    fn closed_error() -> NostrAuthError {
        RpcFailure::SessionClosed.into_connect_error()
    }

    impl Connection {
        /// Close the session for good.
        ///
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
                self.retire_socket(&ws);
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
        fn retire_socket(&self, ws: &web_sys::WebSocket) {
            let current = self.ws.borrow().as_ref() == Some(ws);
            if current {
                *self.ws.borrow_mut() = None;
            }
            close_socket(ws);
            let effects = self.inflight.borrow_mut().fail_socket_lost();
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
        /// The table holding the request.
        inflight: Rc<RefCell<Inflight<W>>>,
        /// The request's id.
        id: String,
    }

    impl<W> RequestGuard<W> {
        /// Guard the request `id`.
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
        /// The attempt's socket.
        ws: web_sys::WebSocket,
        /// Whether dropping the guard closes the socket.
        armed: bool,
    }

    impl AttemptGuard {
        /// Hand the socket over to the caller.
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

    /// Fresh login with a newly generated local pairing keypair.
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

    /// See the facade.
    pub(super) fn close(session: &BunkerSession) {
        session.conn.close();
    }

    /// Restore with the persisted local pairing keypair.
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

    /// NIP-46 `sign_event` over the persistent WebSocket.
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
        checked_event(&request, session.public_key, &returned)
    }

    /// NIP-46 `nip44_encrypt` over the persistent WebSocket.
    pub(super) async fn nip44_encrypt(
        session: &BunkerSession,
        recipient_hex: &str,
        plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        let request = NostrConnectRequest::Nip44Encrypt {
            public_key: peer_key(recipient_hex)?,
            text: plaintext.to_owned(),
        };
        session
            .send_rpc(&request)
            .await
            .and_then(nip44_result)
            .map_err(RpcFailure::into_signing_error)
    }

    /// NIP-46 `nip44_decrypt` over the persistent WebSocket.
    pub(super) async fn nip44_decrypt(
        session: &BunkerSession,
        sender_hex: &str,
        ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        let request = NostrConnectRequest::Nip44Decrypt {
            public_key: peer_key(sender_hex)?,
            ciphertext: ciphertext.to_owned(),
        };
        session
            .send_rpc(&request)
            .await
            .and_then(nip44_result)
            .map_err(RpcFailure::into_signing_error)
    }

    /// Parse the counterparty key of a NIP-44 request.
    fn peer_key(hex: &str) -> Result<PublicKey, NostrAuthError> {
        PublicKey::from_hex(hex).map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))
    }

    impl BunkerSession {
        /// Shared implementation behind [`BunkerSession::connect`] and [`BunkerSession::reconnect`].
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

        /// One relay attempt. Its socket closes on any exit but success.
        async fn handshake_on(
            &self,
            relay: &RelayUrl,
            handshake: &Handshake,
            paired: &mut bool,
        ) -> Result<(PublicKey, web_sys::WebSocket), RpcFailure> {
            let attempt = self.open_relay(relay).await.map_err(RpcFailure::Socket)?;
            if needs_connect(handshake, *paired) {
                let request = connect_request(handshake, self.remote_pubkey);
                connect_result(self.send_on(&attempt.ws, &request).await?)?;
                *paired = true;
            }
            let public_key = public_key_result(
                self.send_on(&attempt.ws, &NostrConnectRequest::GetPublicKey)
                    .await?,
            )?;
            Ok((public_key, attempt.disarm()))
        }

        /// Ensure the persistent WebSocket is open, reconnecting if necessary.
        /// Returns the WebSocket ready to send messages.
        ///
        /// Concurrent callers serialize on `connect_lock`: only the first caller
        /// actually reconnects; subsequent callers wait for that attempt's outcome, up to
        /// `timeout_secs`, instead of each opening their own socket (which would orphan all but
        /// one in-flight RPC until timeout).
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

            let (woken, slot, waker) = wake_pair();
            if let Some(lead) = self.conn.connect_lock.join(waker) {
                let result = self.do_reconnect().await;
                lead.finish(result.as_ref().map(|_| ()).map_err(Clone::clone));
                return result;
            }

            let timer = RpcTimer::start(self.timeout_secs);
            let race = Promise::race(&Array::of2(&woken, timer.fired()));
            let _ = JsFuture::from(race).await;
            let outcome = slot.borrow_mut().take();
            if self.conn.closed.get() {
                return Err(closed_error());
            }
            match outcome {
                None => Err(NostrAuthError::BunkerTimeout),
                Some(Err(e)) => Err(e),
                Some(Ok(())) => self.conn.ws.borrow().as_ref().cloned().ok_or_else(|| {
                    NostrAuthError::BunkerConnectionFailed("reconnect failed".into())
                }),
            }
        }

        /// Tears down any stale socket and opens a new one, trying each relay in order.
        /// Only ever called from `ensure_ws`, which serializes concurrent callers.
        async fn do_reconnect(&self) -> Result<web_sys::WebSocket, NostrAuthError> {
            let old_ws = self.conn.ws.borrow().clone();
            if let Some(old_ws) = old_ws {
                self.conn.retire_socket(&old_ws);
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

        /// Open a socket to `relay`, install the handlers and subscribe.
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

        /// Install the handlers for `ws`. The closures are stored in `handlers`, which drops any
        /// previous handler's captured `client_keys` clone instead of leaking it.
        fn install_handlers(&self, ws: &web_sys::WebSocket) {
            let inflight = Rc::clone(&self.conn.inflight);
            let peer = Peer {
                client: self.client_keys.clone(),
                remote: self.remote_pubkey,
            };
            let on_message = Closure::<dyn FnMut(_)>::new(move |e: web_sys::MessageEvent| {
                let Some(data) = e.data().as_string() else {
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

        /// Post-handshake request: reconnect if needed, then send.
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
                self.conn.retire_socket(&ws);
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
            .ok_or(RpcFailure::Malformed(REQUEST_BUILD_FAILED))?;

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

    /// Generate a cryptographically random request ID using `window.crypto.getRandomValues`.
    fn generate_request_id() -> String {
        random_bytes(8).iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02X}");
            acc
        })
    }
}

/// Server stubs.
#[cfg(feature = "ssr")]
mod imp {
    use super::BunkerSession;
    use crate::signers::NOT_ON_SERVER;
    use crate::types::NostrAuthError;

    /// Server stub for `connect`.
    pub(super) async fn connect(
        _uri: &str,
        _timeout_secs: u32,
    ) -> Result<BunkerSession, NostrAuthError> {
        Err(NostrAuthError::BunkerConnectionFailed(NOT_ON_SERVER.into()))
    }

    /// Server stub for `reconnect`.
    pub(super) async fn reconnect(
        _uri_without_secret: &str,
        _timeout_secs: u32,
        _client_secret_hex: &str,
    ) -> Result<BunkerSession, NostrAuthError> {
        Err(NostrAuthError::BunkerConnectionFailed(NOT_ON_SERVER.into()))
    }

    /// Server stub for `sign_event`.
    pub(super) async fn sign_event(
        _session: &BunkerSession,
        _event_json: &str,
    ) -> Result<String, NostrAuthError> {
        Err(NostrAuthError::SigningFailed(NOT_ON_SERVER.into()))
    }

    /// Server stub for `nip44_encrypt`.
    pub(super) async fn nip44_encrypt(
        _session: &BunkerSession,
        _recipient_hex: &str,
        _plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        Err(NostrAuthError::SigningFailed(NOT_ON_SERVER.into()))
    }

    /// Server stub for `nip44_decrypt`.
    pub(super) async fn nip44_decrypt(
        _session: &BunkerSession,
        _sender_hex: &str,
        _ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        Err(NostrAuthError::SigningFailed(NOT_ON_SERVER.into()))
    }

    /// Server stub for `close`.
    pub(super) const fn close(_session: &BunkerSession) {}

    /// Server stub for `current_auth_url`. No state may cross requests.
    pub(super) const fn current_auth_url() -> Option<String> {
        None
    }

    /// Server stub for `dismiss_auth_prompt`.
    pub(super) const fn dismiss_auth_prompt() {}

    /// Server stub for `register_auth_presenter`.
    pub(super) const fn register_auth_presenter() {}

    /// Server stub for `unregister_auth_presenter`.
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

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn closed_session_through_trait_on_wasm() {
        use crate::signers::signer_traits::tests::unsigned;
        use nostr::event::AsyncSignEvent;
        let s = session();
        let pk = s.public_key;
        s.conn.close();
        let auth = crate::types::AuthResult::Bunker(Box::new(s));
        let r = auth.sign_event_async(unsigned(pk)).await;
        assert!(matches!(r, Err(NostrAuthError::BunkerSessionClosed)));
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
        let want = "Signing failed: not available on server";
        assert_eq!(text(ready(s.sign_event("{}"))), want);
        assert_eq!(text(ready(s.nip44_encrypt("a", "b"))), want);
        assert_eq!(text(ready(s.nip44_decrypt("a", "b"))), want);
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
