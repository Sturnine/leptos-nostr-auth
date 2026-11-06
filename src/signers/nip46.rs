use nostr::key::{Keys, PublicKey};
use nostr::types::RelayUrl;

use crate::types::NostrAuthError;

/// An established NIP-46 remote signing session.
///
/// Maintains a persistent WebSocket to the relay — reused across `sign_event` calls
/// so each signing request does not pay the full connection setup cost.
///
/// `Clone` is shallow: every clone shares the same underlying WebSocket, message
/// handler, and in-flight request table via `Rc<RefCell<_>>`. This is intentional —
/// all clones (e.g. from repeated reads of a reactive `Signal<AuthResult>`) refer
/// to one physical connection, not independent snapshots. Concurrent reconnects
/// across clones are serialized by `connect_lock` in `ensure_ws`.
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
    /// Persistent WebSocket — opened by the handshake, reopened by `ensure_ws` if lost.
    #[cfg(not(feature = "ssr"))]
    ws: send_wrapper::SendWrapper<imp::WsSlot>,
    /// Current onmessage handler for `ws` — replaced (not leaked) on reconnect,
    /// so reconnects don't accumulate closures holding `client_keys` clones.
    #[cfg(not(feature = "ssr"))]
    message_handler: send_wrapper::SendWrapper<imp::MessageHandlerSlot>,
    /// Requests awaiting a response.
    #[cfg(not(feature = "ssr"))]
    inflight: send_wrapper::SendWrapper<imp::InflightSlot>,
    /// Set while a reconnect is in flight; a concurrent caller awaits this
    /// promise instead of racing a second WebSocket into existence, then
    /// reads the winner's result off `ws`. See `ensure_ws`.
    #[cfg(not(feature = "ssr"))]
    connect_lock: send_wrapper::SendWrapper<imp::ConnectLock>,
}

impl BunkerSession {
    /// Establish a NIP-46 connection from a `bunker://` URI (fresh login).
    ///
    /// Generates a new ephemeral local pairing keypair for this session. To restore a
    /// previously-authorized session without the bunker's one-time secret, the crate-internal
    /// `BunkerSession::reconnect` (used by session restore) is used instead.
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features, when connection fails,
    /// or when given a `nostrconnect://` URI (client-initiated pairing is not
    /// yet supported).
    pub async fn connect(uri: &str, timeout_secs: u32) -> Result<Self, NostrAuthError> {
        imp::connect(uri, timeout_secs).await
    }

    /// Reconnect a previously-authorized session without the bunker's original pairing secret.
    ///
    /// `client_secret_hex` is the hex secret of the *local* NIP-46 pairing keypair generated
    /// by the original [`BunkerSession::connect`] call — never the user's Nostr identity key,
    /// never the bunker's one-time secret. Per NIP-46, that secret is single-use and the remote
    /// signer is expected to already recognize this client's public key from the original
    /// pairing, so no secret needs to be resent. If the remote signer has forgotten this client
    /// (access revoked, or a non-compliant bunker that doesn't retain authorization), this call
    /// fails and the caller should fall back to prompting the user to reconnect from scratch.
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

    /// Send a NIP-46 `sign_event` request to the remote signer.
    ///
    /// Reuses the persistent WebSocket if it is open; reconnects automatically if not.
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when signing fails..
    pub async fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        imp::sign_event(self, event_json).await
    }

    /// NIP-44 encrypt via the remote signer (NIP-46 `nip44_encrypt` method).
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when nip44 decryption fails.
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
    /// Returns an error when called with SSR features or when nip44 decryption fails.
    pub async fn nip44_decrypt(
        &self,
        sender_hex: &str,
        ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        imp::nip44_decrypt(self, sender_hex, ciphertext).await
    }
}

/// Browser implementation.
#[cfg(not(feature = "ssr"))]
mod imp {
    use core::cell::RefCell;
    use core::fmt::Write;
    use js_sys::{Array, Promise};
    use nostr::key::{Keys, PublicKey, SecretKey};
    use nostr::nips::nip46::{NostrConnectRequest, ResponseResult};
    use nostr::types::RelayUrl;
    use send_wrapper::SendWrapper;
    use std::rc::Rc;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;

    use super::BunkerSession;
    use crate::signers::browser::{
        js_err_msg, make_rpc_promise, make_timeout_promise, now_timestamp, random_bytes,
    };
    use crate::signers::nip46_protocol::{
        AUTH_URL_TIMEOUT_SECS, AttemptLog, BunkerTarget, DeadlineAction, Effect, Handshake,
        Inflight, Peer, REQUEST_BUILD_FAILED, RpcFailure, connect_request, connect_result,
        event_frame, needs_connect, nip44_result, parse_bunker_uri, persisted_uri,
        public_key_result, request_event, request_message, rotate_to_front, signed_event_result,
        subscribe_frame, unsigned_for_signing,
    };
    use crate::types::NostrAuthError;

    /// How a settled request reaches the call awaiting it.
    type Outcome = Result<ResponseResult, RpcFailure>;

    /// Wakes `send_on`. The typed outcome goes through the slot, so the promise is only a wake-up
    /// and no error text has to survive a trip through JS.
    pub(super) struct RpcWaker {
        /// Read by the waiting call once woken.
        slot: Rc<RefCell<Option<Outcome>>>,
        /// Resolves the promise the waiting call races.
        resolve: js_sys::Function,
    }

    impl RpcWaker {
        /// Hand over the outcome and wake the waiting call.
        fn wake(self, outcome: Outcome) {
            *self.slot.borrow_mut() = Some(outcome);
            let _ = self.resolve.call0(&JsValue::UNDEFINED);
        }
    }

    /// Requests awaiting a response.
    pub(super) type InflightSlot = Rc<RefCell<Inflight<RpcWaker>>>;

    /// Slot holding the current persistent-WebSocket `onmessage` closure.
    /// Replacing it (rather than `Closure::forget()`-ing every reconnect's handler)
    /// drops the previous closure's captured `client_keys` clone promptly.
    pub(super) type MessageHandlerSlot =
        Rc<RefCell<Option<Closure<dyn FnMut(web_sys::MessageEvent)>>>>;

    /// Persistent WebSocket slot.
    pub(super) type WsSlot = Rc<RefCell<Option<web_sys::WebSocket>>>;

    /// In-flight reconnect promise slot.
    pub(super) type ConnectLock = Rc<RefCell<Option<Promise>>>;

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
    fn close_socket(ws: &web_sys::WebSocket) {
        ws.set_onmessage(None);
        ws.set_onopen(None);
        ws.set_onerror(None);
        let _ = ws.close();
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
        let unsigned = unsigned_for_signing(event_json, session.public_key)?;
        session
            .send_rpc(&NostrConnectRequest::SignEvent(unsigned))
            .await
            .and_then(signed_event_result)
            .map_err(RpcFailure::into_signing_error)
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
                ws: SendWrapper::new(Rc::new(RefCell::new(None))),
                message_handler: SendWrapper::new(Rc::new(RefCell::new(None))),
                inflight: SendWrapper::new(Rc::new(RefCell::new(Inflight::default()))),
                connect_lock: SendWrapper::new(Rc::new(RefCell::new(None))),
            };
            let mut paired = false;
            let mut failures = AttemptLog::default();
            for relay in &transport.relays {
                match transport.handshake_on(relay, &handshake, &mut paired).await {
                    Ok((public_key, ws)) => {
                        *transport.ws.borrow_mut() = Some(ws);
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
        /// actually reconnects; subsequent callers await that attempt's result
        /// instead of each opening their own socket (which would orphan all but
        /// one in-flight RPC until timeout).
        async fn ensure_ws(&self) -> Result<web_sys::WebSocket, NostrAuthError> {
            if let Some(ws) = self.ws.borrow().as_ref()
                && ws.ready_state() == web_sys::WebSocket::OPEN
            {
                return Ok(ws.clone());
            }

            // Someone else is already (re)connecting — await their result.
            let in_flight = self.connect_lock.borrow().clone();
            if let Some(promise) = in_flight {
                JsFuture::from(promise).await.map_err(|e| {
                    let msg = e.as_string().unwrap_or_else(|| "connect failed".into());
                    if msg == "timeout" {
                        NostrAuthError::BunkerTimeout
                    } else {
                        NostrAuthError::BunkerConnectionFailed(msg)
                    }
                })?;
                return self.ws.borrow().as_ref().cloned().ok_or_else(|| {
                    NostrAuthError::BunkerConnectionFailed("reconnect failed".into())
                });
            }

            // We're the leader: publish a shared promise so concurrent callers
            // can await this attempt instead of starting their own.
            let (lock_promise, lock_resolve, lock_reject) = make_rpc_promise();
            *self.connect_lock.borrow_mut() = Some(lock_promise);

            let result = self.do_reconnect().await;

            *self.connect_lock.borrow_mut() = None;
            match &result {
                Ok(_) => {
                    let _ = lock_resolve.call1(&JsValue::UNDEFINED, &JsValue::UNDEFINED);
                }
                Err(e) => {
                    let _ =
                        lock_reject.call1(&JsValue::UNDEFINED, &JsValue::from_str(&e.to_string()));
                }
            }

            result
        }

        /// Tears down any stale socket and opens a new one, trying each relay in order.
        /// Only ever called from `ensure_ws`, which serializes concurrent callers.
        async fn do_reconnect(&self) -> Result<web_sys::WebSocket, NostrAuthError> {
            if let Some(old_ws) = self.ws.borrow_mut().take() {
                close_socket(&old_ws);
            }
            let mut last = NostrAuthError::BunkerConnectionFailed("no relay to try".into());
            for relay in &self.relays {
                match self.open_relay(relay).await {
                    Ok(attempt) => {
                        let ws = attempt.disarm();
                        *self.ws.borrow_mut() = Some(ws.clone());
                        return Ok(ws);
                    }
                    Err(e) => last = e,
                }
            }
            Err(last)
        }

        /// Open a socket to `relay`, install the handler and subscribe.
        async fn open_relay(&self, relay: &RelayUrl) -> Result<AttemptGuard, NostrAuthError> {
            let ws = web_sys::WebSocket::new(relay.as_str()).map_err(|e| {
                NostrAuthError::BunkerConnectionFailed(format!("WebSocket: {}", js_err_msg(&e)))
            })?;
            let attempt = AttemptGuard {
                ws: ws.clone(),
                armed: true,
            };
            ws.set_binary_type(web_sys::BinaryType::Arraybuffer);
            self.inflight.borrow_mut().reset_socket();
            self.install_message_handler(&ws);

            let (open_promise, open_resolve, open_reject) = make_rpc_promise();
            let on_open = Closure::<dyn FnMut(_)>::new(move |_: web_sys::Event| {
                let _ = open_resolve.call1(&JsValue::UNDEFINED, &JsValue::UNDEFINED);
            });
            let on_error_open = Closure::<dyn FnMut(_)>::new(move |_: web_sys::Event| {
                let _ = open_reject.call1(
                    &JsValue::UNDEFINED,
                    &JsValue::from_str("WebSocket error during connection"),
                );
            });
            ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
            ws.set_onerror(Some(on_error_open.as_ref().unchecked_ref()));

            let timeout_promise = make_timeout_promise(self.timeout_secs);
            let race = Promise::race(&Array::of2(&open_promise, &timeout_promise));
            let opened = JsFuture::from(race).await;

            ws.set_onopen(None);
            ws.set_onerror(None);

            opened.map_err(|e| {
                let msg = e.as_string().unwrap_or_else(|| "connect failed".into());
                if msg == "timeout" {
                    NostrAuthError::BunkerTimeout
                } else {
                    NostrAuthError::BunkerConnectionFailed(msg)
                }
            })?;

            ws.send_with_str(&subscribe_frame(self.client_keys.public_key()))
                .map_err(|e| NostrAuthError::BunkerConnectionFailed(js_err_msg(&e)))?;
            Ok(attempt)
        }

        /// Install the handler for `ws`. The closure is stored in `message_handler`, which drops
        /// any previous handler's captured `client_keys` clone instead of leaking it.
        fn install_message_handler(&self, ws: &web_sys::WebSocket) {
            let inflight = Rc::clone(&self.inflight);
            let peer = Peer {
                client: self.client_keys.clone(),
                remote: self.remote_pubkey,
            };
            let on_message = Closure::<dyn FnMut(_)>::new(move |e: web_sys::MessageEvent| {
                let Some(data) = e.data().as_string() else {
                    return;
                };
                let effects = inflight.borrow_mut().on_frame(&data, &peer);
                for effect in effects {
                    match effect {
                        Effect::Settle { waker, outcome } => waker.wake(outcome),
                        Effect::CloseSocket => {
                            if let Some(ws) = e
                                .target()
                                .and_then(|t| t.dyn_into::<web_sys::WebSocket>().ok())
                            {
                                close_socket(&ws);
                            }
                        }
                    }
                }
            });
            ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
            *self.message_handler.borrow_mut() = Some(on_message);
        }

        /// Post-handshake request: reconnect if needed, then send.
        async fn send_rpc(&self, request: &NostrConnectRequest) -> Outcome {
            let ws = self.ensure_ws().await.map_err(RpcFailure::Socket)?;
            self.send_on(&ws, request).await
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

            let slot = Rc::new(RefCell::new(None));
            let (woken, resolve, _) = make_rpc_promise();
            self.inflight.borrow_mut().insert(
                id.clone(),
                request.method(),
                event.id,
                RpcWaker {
                    slot: Rc::clone(&slot),
                    resolve,
                },
            );
            let _guard = RequestGuard::new(Rc::clone(&self.inflight), id.clone());

            ws.send_with_str(&event_frame(&event)).map_err(|e| {
                RpcFailure::Socket(NostrAuthError::BunkerConnectionFailed(js_err_msg(&e)))
            })?;

            let mut wait_secs = self.timeout_secs;
            loop {
                let timer = make_timeout_promise(wait_secs);
                let race = Promise::race(&Array::of2(&woken, &timer));
                let woke = JsFuture::from(race).await.is_ok();
                if let Some(outcome) = slot.borrow_mut().take() {
                    return outcome;
                }
                if woke {
                    continue;
                }
                let mut inflight = self.inflight.borrow_mut();
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

    /// Whether a mounted `NostrAuthModal` can show a link.
    const fn presenter_mounted() -> bool {
        false
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
}

#[cfg(test)]
#[cfg(not(feature = "ssr"))]
mod tests {
    use super::*;
    use crate::signers::nip46_protocol::Inflight;
    use core::cell::RefCell;
    use nostr::event::EventId;
    use nostr::nips::nip46::NostrConnectMethod;
    use std::rc::Rc;

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
        assert!(inflight.borrow().contains("a"));
        drop(guard);
        assert!(!inflight.borrow().contains("a"));
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
}
