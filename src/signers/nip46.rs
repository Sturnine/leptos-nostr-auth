#[cfg(not(feature = "ssr"))]
use core::cell::RefCell;
#[cfg(not(feature = "ssr"))]
use core::fmt::Write;
#[cfg(not(feature = "ssr"))]
use js_sys::{Array, Promise};
#[cfg(not(feature = "ssr"))]
use nostr::event::{Event, FinalizeEvent, Kind, Tag, UnsignedEvent};
#[cfg(not(feature = "ssr"))]
use nostr::key::SecretKey;
use nostr::key::{Keys, PublicKey};
#[cfg(not(feature = "ssr"))]
use nostr::types::Timestamp;
#[cfg(not(feature = "ssr"))]
use send_wrapper::SendWrapper;
#[cfg(not(feature = "ssr"))]
use std::collections::HashMap;
#[cfg(not(feature = "ssr"))]
use std::rc::Rc;
#[cfg(not(feature = "ssr"))]
use wasm_bindgen::prelude::*;
#[cfg(not(feature = "ssr"))]
use wasm_bindgen_futures::JsFuture;

#[cfg(not(feature = "ssr"))]
use super::browser::{make_rpc_promise, make_timeout_promise, now_timestamp, random_bytes};
use crate::types::NostrAuthError;

/// Parsed bunker:// URI components — only needed in WASM (all callers are gated).
#[cfg(not(feature = "ssr"))]
struct BunkerUri {
    /// Remote signer's public key, lowercase hex.
    remote_pubkey_hex: String,
    /// Relay URL to connect through.
    relay_url: String,
    /// Optional one-time pairing secret (never persisted — see `BunkerSession::reconnect`).
    secret: Option<String>,
}

/// Parse a `bunker://<remote-pubkey>?relay=<url>&secret=<secret>` URI.
#[cfg(not(feature = "ssr"))]
fn parse_bunker_uri(uri: &str) -> Result<BunkerUri, NostrAuthError> {
    if uri.starts_with("nostrconnect://") {
        return Err(NostrAuthError::InvalidBunkerUri(
            "nostrconnect:// (client-initiated pairing) is not yet supported — \
             paste the bunker:// URI shown by your remote signer instead"
                .into(),
        ));
    }

    let stripped = uri
        .strip_prefix("bunker://")
        .ok_or_else(|| NostrAuthError::InvalidBunkerUri("URI must start with bunker://".into()))?;

    let (pubkey_part, query) = stripped.split_once('?').unwrap_or((stripped, ""));
    let remote_pubkey_hex = pubkey_part.to_lowercase();

    if remote_pubkey_hex.is_empty() {
        return Err(NostrAuthError::InvalidBunkerUri(
            "missing remote pubkey".into(),
        ));
    }

    let mut relay_url = String::new();
    let mut secret = None;

    for pair in query.split('&').filter(|s| !s.is_empty()) {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "relay" => relay_url = urlencoding_decode(v),
                "secret" => secret = Some(urlencoding_decode(v)),
                _ => {}
            }
        }
    }

    if relay_url.is_empty() {
        return Err(NostrAuthError::InvalidBunkerUri("missing relay URL".into()));
    }

    Ok(BunkerUri {
        remote_pubkey_hex,
        relay_url,
        secret,
    })
}

/// Percent-decode a `bunker://` URI query value.
#[cfg(not(feature = "ssr"))]
fn urlencoding_decode(s: &str) -> String {
    js_sys::decode_uri_component(s).map_or_else(
        |_| s.to_owned(),
        |v| v.as_string().unwrap_or_else(|| s.to_owned()),
    )
}

/// Percent-encode a string for use as a `bunker://` URI query value.
#[cfg(not(feature = "ssr"))]
fn urlencoding_encode(s: &str) -> String {
    js_sys::encode_uri_component(s)
        .as_string()
        .unwrap_or_else(|| s.to_owned())
}

/// Pending RPC callbacks: maps request ID → `Box<dyn Fn(Result<String, String>)>`.
/// Each callback is called exactly once when the response arrives or an error occurs.
#[cfg(not(feature = "ssr"))]
type PendingMap = Rc<RefCell<HashMap<String, Box<dyn Fn(Result<String, String>)>>>>;

/// Slot holding the current persistent-WebSocket `onmessage` closure.
/// Replacing it (rather than `Closure::forget()`-ing every reconnect's handler)
/// drops the previous closure's captured `client_keys` clone promptly.
#[cfg(not(feature = "ssr"))]
type MessageHandlerSlot = Rc<RefCell<Option<Closure<dyn FnMut(web_sys::MessageEvent)>>>>;

/// An established NIP-46 remote signing session.
///
/// Maintains a persistent WebSocket to the relay — reused across `sign_event` calls
/// so each signing request does not pay the full connection setup cost.
///
/// `Clone` is shallow: every clone shares the same underlying WebSocket, message
/// handler, and pending-request map via `Rc<RefCell<_>>`. This is intentional —
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
    /// WebSocket relay URL.
    relay_url: String,
    /// Persistent WebSocket — lazily opened on first `sign_event` call, reused thereafter.
    #[cfg(not(feature = "ssr"))]
    ws: SendWrapper<Rc<RefCell<Option<web_sys::WebSocket>>>>,
    /// Current onmessage handler for `ws` — replaced (not leaked) on reconnect,
    /// so reconnects don't accumulate closures holding `client_keys` clones.
    #[cfg(not(feature = "ssr"))]
    message_handler: SendWrapper<MessageHandlerSlot>,
    /// Pending RPC callbacks keyed by request ID.
    #[cfg(not(feature = "ssr"))]
    pending: SendWrapper<PendingMap>,
    /// Set while a reconnect is in flight; a concurrent caller awaits this
    /// promise instead of racing a second WebSocket into existence, then
    /// reads the winner's result off `ws`. See `ensure_ws`.
    #[cfg(not(feature = "ssr"))]
    connect_lock: SendWrapper<Rc<RefCell<Option<Promise>>>>,
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
        #[cfg(feature = "ssr")]
        {
            let _ = (uri, timeout_secs);
            Err(NostrAuthError::BunkerConnectionFailed(
                "not available on server".into(),
            ))
        }

        #[cfg(not(feature = "ssr"))]
        {
            Self::connect_with_keys(uri, timeout_secs, Keys::generate()).await
        }
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
    /// Only called from `storage::restore_session`, which is itself client-only — no SSR stub
    /// is needed here (unlike `connect`, which is public API called directly from the modal).
    ///
    /// # Errors
    ///
    /// Returns an error when `client_secret_hex` is not a valid secret key, or when
    /// reconnection fails.
    #[cfg(not(feature = "ssr"))]
    pub(crate) async fn reconnect(
        uri_without_secret: &str,
        timeout_secs: u32,
        client_secret_hex: &str,
    ) -> Result<Self, NostrAuthError> {
        let secret_key = SecretKey::from_hex(client_secret_hex)
            .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;
        Self::connect_with_keys(uri_without_secret, timeout_secs, Keys::new(secret_key)).await
    }

    /// Shared implementation behind [`BunkerSession::connect`] and [`BunkerSession::reconnect`].
    #[cfg(not(feature = "ssr"))]
    async fn connect_with_keys(
        uri: &str,
        timeout_secs: u32,
        client_keys: Keys,
    ) -> Result<Self, NostrAuthError> {
        let parsed = parse_bunker_uri(uri)?;

        let remote_pubkey = PublicKey::from_hex(&parsed.remote_pubkey_hex)
            .map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))?;

        let client_pubkey_hex = client_keys.public_key().to_hex();

        // NIP-46 connect request payload
        let req_id = generate_request_id();
        let params = parsed.secret.as_deref().map_or_else(
            || {
                serde_json::json!({
                    "id": req_id,
                    "method": "connect",
                    "params": [client_pubkey_hex, "", "sign_event,get_public_key,nip44_encrypt,nip44_decrypt"]
                })
            },
            |s| {
                serde_json::json!({
                    "id": req_id,
                    "method": "connect",
                    "params": [client_pubkey_hex, s, "sign_event,get_public_key,nip44_encrypt,nip44_decrypt"]
                })
            },
        );

        let req_json = serde_json::to_string(&params)
            .map_err(|e| NostrAuthError::Serialization(e.to_string()))?;

        // Encrypt request with NIP-44 using client secret key
        let encrypted = nostr::nips::nip44::encrypt(
            client_keys.secret_key(),
            &remote_pubkey,
            &req_json,
            nostr::nips::nip44::Version::V2,
        )
        .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;

        // Build a kind:24133 event signed by client ephemeral key
        let event = nip46_event(&client_keys, remote_pubkey, encrypted, now_timestamp())
            .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;

        let event_json = event.as_json();

        // Do the one-shot connect handshake (opens + closes a WS)
        let remote_pubkey_hex = parsed.remote_pubkey_hex.clone();
        let relay_url = parsed.relay_url.clone();

        let result_pubkey = websocket_connect_handshake(
            &relay_url,
            &event_json,
            &client_pubkey_hex,
            &remote_pubkey_hex,
            &client_keys,
            &req_id,
            timeout_secs,
        )
        .await?;

        // Secret-stripped reconstruction: the bunker's one-time pairing secret (if any)
        // is intentionally dropped here so it never lives in `bunker_uri` beyond this
        // function — see `PersistedSession::bunker_client_secret_hex` for what gets
        // persisted instead.
        let bunker_uri = format!(
            "bunker://{remote_pubkey_hex}?relay={}",
            urlencoding_encode(&relay_url)
        );

        Ok(Self {
            public_key: result_pubkey,
            bunker_uri,
            timeout_secs,
            client_keys,
            remote_pubkey,
            relay_url,
            ws: SendWrapper::new(Rc::new(RefCell::new(None))),
            message_handler: SendWrapper::new(Rc::new(RefCell::new(None))),
            pending: SendWrapper::new(Rc::new(RefCell::new(HashMap::new()))),
            connect_lock: SendWrapper::new(Rc::new(RefCell::new(None))),
        })
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
        #[cfg(feature = "ssr")]
        {
            let _ = event_json;
            Err(NostrAuthError::SigningFailed(
                "not available on server".into(),
            ))
        }

        #[cfg(not(feature = "ssr"))]
        {
            let req_id = generate_request_id();
            let req = serde_json::json!({
                "id": req_id,
                "method": "sign_event",
                "params": [serde_json::from_str::<serde_json::Value>(event_json)
                    .map_err(|e| NostrAuthError::Serialization(e.to_string()))?]
            });
            let req_json = serde_json::to_string(&req)
                .map_err(|e| NostrAuthError::Serialization(e.to_string()))?;

            let result_json = self.send_rpc(&req_id, &req_json).await?;

            // Parse the JSON-stringified result
            let v: serde_json::Value = serde_json::from_str(&result_json)
                .map_err(|e| NostrAuthError::SigningFailed(e.to_string()))?;
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| NostrAuthError::SigningFailed("invalid sign_event response".into()))
        }
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
        #[cfg(feature = "ssr")]
        {
            let _ = (recipient_hex, plaintext);
            Err(NostrAuthError::SigningFailed(
                "not available on server".into(),
            ))
        }

        #[cfg(not(feature = "ssr"))]
        {
            let req_id = generate_request_id();
            let req = serde_json::json!({
                "id": req_id,
                "method": "nip44_encrypt",
                "params": [recipient_hex, plaintext]
            });
            let req_json = serde_json::to_string(&req)
                .map_err(|e| NostrAuthError::Serialization(e.to_string()))?;

            let result_json = self.send_rpc(&req_id, &req_json).await?;
            let v: serde_json::Value = serde_json::from_str(&result_json)
                .map_err(|e| NostrAuthError::SigningFailed(e.to_string()))?;
            v.as_str().map(str::to_owned).ok_or_else(|| {
                NostrAuthError::SigningFailed("invalid nip44_encrypt response".into())
            })
        }
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
        #[cfg(feature = "ssr")]
        {
            let _ = (sender_hex, ciphertext);
            Err(NostrAuthError::SigningFailed(
                "not available on server".into(),
            ))
        }

        #[cfg(not(feature = "ssr"))]
        {
            let req_id = generate_request_id();
            let req = serde_json::json!({
                "id": req_id,
                "method": "nip44_decrypt",
                "params": [sender_hex, ciphertext]
            });
            let req_json = serde_json::to_string(&req)
                .map_err(|e| NostrAuthError::Serialization(e.to_string()))?;

            let result_json = self.send_rpc(&req_id, &req_json).await?;
            let v: serde_json::Value = serde_json::from_str(&result_json)
                .map_err(|e| NostrAuthError::SigningFailed(e.to_string()))?;
            v.as_str().map(str::to_owned).ok_or_else(|| {
                NostrAuthError::SigningFailed("invalid nip44_decrypt response".into())
            })
        }
    }

    /// Ensure the persistent WebSocket is open, reconnecting if necessary.
    /// Returns the WebSocket ready to send messages.
    ///
    /// Concurrent callers serialize on `connect_lock`: only the first caller
    /// actually reconnects; subsequent callers await that attempt's result
    /// instead of each opening their own socket (which would orphan all but
    /// one in-flight RPC until timeout).
    #[cfg(not(feature = "ssr"))]
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
            return self
                .ws
                .borrow()
                .as_ref()
                .cloned()
                .ok_or_else(|| NostrAuthError::BunkerConnectionFailed("reconnect failed".into()));
        }

        // We're the leader: publish a shared promise so concurrent callers
        // can await this attempt instead of starting their own.
        let (lock_promise, lock_resolve, lock_reject) = make_rpc_promise();
        *self.connect_lock.borrow_mut() = Some(lock_promise);

        let result = self.do_reconnect().await;

        *self.connect_lock.borrow_mut() = None;
        match &result {
            Ok(_) => {
                if let Some(f) = &lock_resolve {
                    let _ = f.call1(&JsValue::UNDEFINED, &JsValue::UNDEFINED);
                }
            }
            Err(e) => {
                if let Some(f) = &lock_reject {
                    let _ = f.call1(&JsValue::UNDEFINED, &JsValue::from_str(&e.to_string()));
                }
            }
        }

        result
    }

    /// Actually tears down any stale socket and opens + waits for a new one.
    /// Only ever called from `ensure_ws`, which serializes concurrent callers.
    #[cfg(not(feature = "ssr"))]
    async fn do_reconnect(&self) -> Result<web_sys::WebSocket, NostrAuthError> {
        // Tear down any stale socket before reconnecting so its handlers can't
        // fire against the new connection and its closure is dropped cleanly.
        if let Some(old_ws) = self.ws.borrow_mut().take() {
            old_ws.set_onmessage(None);
            old_ws.set_onopen(None);
            old_ws.set_onerror(None);
            let _ = old_ws.close();
        }

        // Open a new persistent WS
        let ws = web_sys::WebSocket::new(&self.relay_url)
            .map_err(|e| NostrAuthError::BunkerConnectionFailed(format!("WebSocket: {e:?}")))?;
        ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

        // Set up the persistent message handler referencing our pending map
        setup_persistent_message_handler(
            &ws,
            &self.pending,
            &self.client_keys,
            &self.remote_pubkey,
            &self.message_handler,
        );

        // Wait for open, then send REQ subscription
        let client_pk_hex = self.client_keys.public_key().to_hex();
        let ws_for_open = ws.clone();

        let (open_promise, open_resolve, open_reject) = make_rpc_promise();

        let on_open = Closure::<dyn FnMut(_)>::new(move |_: web_sys::Event| {
            let sub_id = "nip46-persistent";
            let req_msg = serde_json::json!([
                "REQ",
                sub_id,
                {"kinds": [24133], "#p": [client_pk_hex]}
            ]);
            let _ = ws_for_open.send_with_str(&req_msg.to_string());
            if let Some(f) = &open_resolve {
                let _ = f.call1(&JsValue::UNDEFINED, &JsValue::UNDEFINED);
            }
        });

        let on_error_open = Closure::<dyn FnMut(_)>::new(move |_: web_sys::ErrorEvent| {
            if let Some(f) = &open_reject {
                let _ = f.call1(
                    &JsValue::UNDEFINED,
                    &JsValue::from_str("WebSocket error during reconnect"),
                );
            }
        });

        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        ws.set_onerror(Some(on_error_open.as_ref().unchecked_ref()));

        // Race open against timeout
        let timeout_promise = make_timeout_promise(self.timeout_secs);
        let race = js_sys::Promise::race(&Array::of2(&open_promise, &timeout_promise));

        // Hold closures alive until the race resolves
        let result = JsFuture::from(race).await;

        // Clear one-shot open/error handlers
        ws.set_onopen(None);
        ws.set_onerror(None);
        drop(on_open);
        drop(on_error_open);

        result.map_err(|e| {
            let msg = e.as_string().unwrap_or_else(|| "connect failed".into());
            if msg == "timeout" {
                NostrAuthError::BunkerTimeout
            } else {
                NostrAuthError::BunkerConnectionFailed(msg)
            }
        })?;

        *self.ws.borrow_mut() = Some(ws.clone());
        Ok(ws)
    }

    /// Encrypt a request, send it over the persistent WS, and await the response.
    #[cfg(not(feature = "ssr"))]
    async fn send_rpc(&self, req_id: &str, req_json: &str) -> Result<String, NostrAuthError> {
        let ws = self.ensure_ws().await?;

        // Encrypt with NIP-44
        let encrypted = nostr::nips::nip44::encrypt(
            self.client_keys.secret_key(),
            &self.remote_pubkey,
            req_json,
            nostr::nips::nip44::Version::V2,
        )
        .map_err(|e| NostrAuthError::SigningFailed(e.to_string()))?;

        // Build and sign the kind:24133 event
        let event = nip46_event(
            &self.client_keys,
            self.remote_pubkey,
            encrypted,
            now_timestamp(),
        )
        .map_err(|e| NostrAuthError::SigningFailed(e.to_string()))?;

        // Register a promise in the pending map before sending
        let (response_promise, resolve_fn, reject_fn) = make_rpc_promise();
        let req_id_owned = req_id.to_owned();
        let pending_clone = self.pending.clone();
        let req_id_for_cleanup = req_id_owned.clone();

        self.pending.borrow_mut().insert(
            req_id_owned,
            Box::new(move |result: Result<String, String>| match result {
                Ok(v) => {
                    if let Some(f) = &resolve_fn {
                        let _ = f.call1(&JsValue::UNDEFINED, &JsValue::from_str(&v));
                    }
                }
                Err(e) => {
                    if let Some(f) = &reject_fn {
                        let _ = f.call1(&JsValue::UNDEFINED, &JsValue::from_str(&e));
                    }
                }
            }),
        );

        // Send the EVENT message
        let event_msg = serde_json::json!([
            "EVENT",
            serde_json::from_str::<serde_json::Value>(&event.as_json()).unwrap_or_default()
        ]);
        ws.send_with_str(&event_msg.to_string())
            .map_err(|e| NostrAuthError::SigningFailed(format!("send failed: {e:?}")))?;

        // Race against timeout
        let timeout_promise = make_timeout_promise(self.timeout_secs);
        let race = js_sys::Promise::race(&Array::of2(&response_promise, &timeout_promise));

        let result = JsFuture::from(race).await.map_err(|e| {
            // Clean up the pending entry on timeout/error
            pending_clone.borrow_mut().remove(&req_id_for_cleanup);
            let msg = e.as_string().unwrap_or_else(|| "rpc failed".into());
            if msg == "timeout" {
                NostrAuthError::BunkerTimeout
            } else {
                NostrAuthError::BunkerConnectionFailed(msg)
            }
        })?;

        result
            .as_string()
            .ok_or_else(|| NostrAuthError::BunkerConnectionFailed("invalid RPC response".into()))
    }
}

/// Decode a raw relay message as a NIP-46 response event addressed to us.
///
/// Returns `Some((request_id, Ok(result_json) | Err(error_message)))` if `data`
/// is a well-formed `["EVENT", sub_id, event]` message whose event is kind
/// 24133, from `remote_pubkey_hex`, and NIP-44-decrypts to a JSON-RPC-shaped
/// response. Returns `None` for anything else (malformed, wrong kind, wrong
/// sender, undecryptable, or unparseable plaintext) — callers should silently
/// ignore such messages rather than error, since relays may deliver unrelated
/// events on the same subscription.
#[expect(
    clippy::indexing_slicing,
    reason = "serde_json::Value indexing returns Null on a miss and never panics"
)]
#[cfg(not(feature = "ssr"))]
fn decode_nip46_response(
    data: &str,
    client_keys: &Keys,
    remote_pubkey: &PublicKey,
    remote_pubkey_hex: &str,
) -> Option<(String, Result<String, String>)> {
    let msg: serde_json::Value = serde_json::from_str(data).ok()?;
    if msg[0].as_str() != Some("EVENT") {
        return None;
    }
    let event_obj = &msg[2];
    if event_obj["kind"].as_u64() != Some(24133) {
        return None;
    }
    if event_obj["pubkey"].as_str()? != remote_pubkey_hex {
        return None;
    }
    let ciphertext = event_obj["content"].as_str()?;
    let plaintext =
        nostr::nips::nip44::decrypt(client_keys.secret_key(), remote_pubkey, ciphertext).ok()?;
    let resp: serde_json::Value = serde_json::from_str(&plaintext).ok()?;
    let req_id = resp["id"].as_str()?.to_owned();
    let result = resp["error"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map_or_else(|| Ok(resp["result"].to_string()), |err| Err(err.to_owned()));
    Some((req_id, result))
}

/// Install a persistent `onmessage` handler that decrypts NIP-46 responses and
/// dispatches them to the pending map. The closure is stored in `handler_slot`,
/// which drops (and zeroizes) any previous handler's captured `client_keys` clone
/// instead of leaking it — important since this runs on every reconnect.
#[cfg(not(feature = "ssr"))]
fn setup_persistent_message_handler(
    ws: &web_sys::WebSocket,
    pending: &PendingMap,
    client_keys: &Keys,
    remote_pubkey: &PublicKey,
    handler_slot: &MessageHandlerSlot,
) {
    let pending_clone = Rc::clone(pending);
    let keys_clone = client_keys.clone();
    let remote_pk_clone = *remote_pubkey;
    let remote_hex = remote_pubkey.to_hex();

    let on_message = Closure::<dyn FnMut(_)>::new(move |e: web_sys::MessageEvent| {
        let Some(data) = e.data().as_string() else {
            return;
        };
        let Some((req_id, result)) =
            decode_nip46_response(&data, &keys_clone, &remote_pk_clone, &remote_hex)
        else {
            return;
        };
        if let Some(cb) = pending_clone.borrow_mut().remove(&req_id) {
            cb(result);
        }
    });

    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    // Replacing the slot drops any previous handler (and its captured client_keys
    // clone) instead of leaking it, so reconnects don't accumulate key material.
    *handler_slot.borrow_mut() = Some(on_message);
}

/// Performs the NIP-46 connect handshake over a one-shot WebSocket.
/// Returns the remote signer's public key.
#[cfg(not(feature = "ssr"))]
async fn websocket_connect_handshake(
    relay_url: &str,
    event_json: &str,
    client_pubkey_hex: &str,
    remote_pubkey_hex: &str,
    client_keys: &Keys,
    req_id: &str,
    timeout_secs: u32,
) -> Result<PublicKey, NostrAuthError> {
    let result_str = websocket_one_shot_rpc(
        relay_url,
        event_json,
        client_pubkey_hex,
        remote_pubkey_hex,
        client_keys,
        req_id,
        timeout_secs,
    )
    .await?;

    // The result is JSON-stringified (e.g. `"\"ack\""` or `"\"hexpubkey\""`)
    let response: serde_json::Value = serde_json::from_str(&result_str)
        .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;

    let pk_hex = response.as_str().unwrap_or_default();

    if pk_hex == "ack" || pk_hex.is_empty() {
        // Some bunkers ack without returning the pubkey — do a get_public_key call
        return get_bunker_public_key(
            relay_url,
            client_pubkey_hex,
            remote_pubkey_hex,
            client_keys,
            timeout_secs,
        )
        .await;
    }

    PublicKey::from_hex(pk_hex).map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))
}

/// Minimal `get_public_key` RPC call to retrieve the remote signer's pubkey after connect.
#[cfg(not(feature = "ssr"))]
async fn get_bunker_public_key(
    relay_url: &str,
    client_pubkey_hex: &str,
    remote_pubkey_hex: &str,
    client_keys: &Keys,
    timeout_secs: u32,
) -> Result<PublicKey, NostrAuthError> {
    let req_id = generate_request_id();
    let req = serde_json::json!({"id": req_id, "method": "get_public_key", "params": []});
    let req_json =
        serde_json::to_string(&req).map_err(|e| NostrAuthError::Serialization(e.to_string()))?;

    let remote_pk = PublicKey::from_hex(remote_pubkey_hex)
        .map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))?;

    let encrypted = nostr::nips::nip44::encrypt(
        client_keys.secret_key(),
        &remote_pk,
        &req_json,
        nostr::nips::nip44::Version::V2,
    )
    .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;

    let event = nip46_event(client_keys, remote_pk, encrypted, now_timestamp())
        .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;

    let result_str = websocket_one_shot_rpc(
        relay_url,
        &event.as_json(),
        client_pubkey_hex,
        remote_pubkey_hex,
        client_keys,
        &req_id,
        timeout_secs,
    )
    .await?;

    let v: serde_json::Value = serde_json::from_str(&result_str)
        .map_err(|e| NostrAuthError::BunkerConnectionFailed(e.to_string()))?;
    let hex = v
        .as_str()
        .ok_or_else(|| NostrAuthError::BunkerConnectionFailed("no pubkey in response".into()))?;

    PublicKey::from_hex(hex).map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))
}

/// Opens a WebSocket, subscribes, sends one event, waits for the NIP-46 response,
/// then closes the WebSocket. Used only for the initial connect handshake.
///
/// Closures are held in named bindings and dropped at the end of this function
/// (after the `await` resolves) rather than leaked via `.forget()`.
#[cfg(not(feature = "ssr"))]
async fn websocket_one_shot_rpc(
    relay_url: &str,
    event_json: &str,
    client_pubkey_hex: &str,
    remote_pubkey_hex: &str,
    client_keys: &Keys,
    req_id: &str,
    timeout_secs: u32,
) -> Result<String, NostrAuthError> {
    use wasm_bindgen::closure::Closure;

    let (promise, resolve_fn, reject_fn) = make_rpc_promise();

    let resolve_for_msg = resolve_fn.clone();
    let reject_for_msg = reject_fn.clone();

    let client_keys_clone = client_keys.clone();
    let remote_pubkey_hex_owned = remote_pubkey_hex.to_owned();
    let req_id_owned = req_id.to_owned();
    let event_json_owned = event_json.to_owned();
    let client_pubkey_hex_owned = client_pubkey_hex.to_owned();

    let ws = web_sys::WebSocket::new(relay_url)
        .map_err(|e| NostrAuthError::BunkerConnectionFailed(format!("WebSocket: {e:?}")))?;
    ws.set_binary_type(web_sys::BinaryType::Arraybuffer);

    // On open: subscribe and send the event
    let ws_for_open = ws.clone();
    let req_id_for_open = req_id_owned.clone();
    let client_pk_for_open = client_pubkey_hex_owned.clone();
    let on_open = Closure::<dyn FnMut(_)>::new(move |_: web_sys::Event| {
        let sub_id = format!("nip46-{}", &req_id_for_open[..8]);
        let req_msg = serde_json::json!([
            "REQ", sub_id, {"kinds": [24133], "#p": [client_pk_for_open]}
        ]);
        let _ = ws_for_open.send_with_str(&req_msg.to_string());
        let event_msg = serde_json::json!([
            "EVENT",
            serde_json::from_str::<serde_json::Value>(&event_json_owned).unwrap_or_default()
        ]);
        let _ = ws_for_open.send_with_str(&event_msg.to_string());
    });

    // On message: decrypt and resolve if this is our response
    let on_message = Closure::<dyn FnMut(_)>::new(move |e: web_sys::MessageEvent| {
        let Some(data) = e.data().as_string() else {
            return;
        };
        let Ok(remote_pk) = PublicKey::from_hex(&remote_pubkey_hex_owned) else {
            return;
        };
        let Some((req_id, result)) = decode_nip46_response(
            &data,
            &client_keys_clone,
            &remote_pk,
            &remote_pubkey_hex_owned,
        ) else {
            return;
        };
        if req_id != req_id_owned {
            return;
        }
        match result {
            Ok(result_str) => {
                if let Some(f) = &resolve_for_msg {
                    let _ = f.call1(&JsValue::UNDEFINED, &JsValue::from_str(&result_str));
                }
            }
            Err(err) => {
                if let Some(f) = &reject_for_msg {
                    let _ = f.call1(&JsValue::UNDEFINED, &JsValue::from_str(&err));
                }
            }
        }
    });

    let on_error = Closure::<dyn FnMut(_)>::new({
        let reject_fn = reject_fn.clone();
        move |_: web_sys::ErrorEvent| {
            if let Some(f) = &reject_fn {
                let _ = f.call1(&JsValue::UNDEFINED, &JsValue::from_str("WebSocket error"));
            }
        }
    });

    ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    ws.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    // Race the response promise against a timeout
    let timeout_promise = make_timeout_promise(timeout_secs);
    let race = js_sys::Promise::race(&Array::of2(&promise, &timeout_promise));

    // Await — closures are still alive (held by named bindings above)
    let result = JsFuture::from(race).await;

    // Clear handlers and close the one-shot WS; closures drop at end of scope
    ws.set_onopen(None);
    ws.set_onmessage(None);
    ws.set_onerror(None);
    let _ = ws.close();

    // Explicit drops to satisfy the borrow checker (closures captured FnMut, not Copy)
    drop(on_open);
    drop(on_message);
    drop(on_error);

    result
        .map_err(|e| {
            let msg = e.as_string().unwrap_or_else(|| "connection failed".into());
            if msg == "timeout" {
                NostrAuthError::BunkerTimeout
            } else {
                NostrAuthError::BunkerConnectionFailed(msg)
            }
        })?
        .as_string()
        .ok_or_else(|| NostrAuthError::BunkerConnectionFailed("invalid response".into()))
}

/// Generate a cryptographically random request ID using `window.crypto.getRandomValues`.
#[cfg(not(feature = "ssr"))]
fn generate_request_id() -> String {
    random_bytes(8).iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02X}");
        acc
    })
}

/// Build and sign a kind 24133 NIP-46 event addressed to `remote`.
#[cfg(not(feature = "ssr"))]
fn nip46_event(
    client_keys: &Keys,
    remote: PublicKey,
    encrypted_content: String,
    created_at: Timestamp,
) -> Result<Event, nostr::error::Error> {
    UnsignedEvent::new(
        client_keys.public_key(),
        created_at,
        Kind::Custom(24133),
        [Tag::public_key(remote)],
        encrypted_content,
    )
    .finalize(client_keys)
}

#[cfg(test)]
#[cfg(not(feature = "ssr"))]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod tests {
    use super::*;

    #[cfg(not(feature = "ssr"))]
    #[test]
    fn nip46_event_shape() {
        let client = Keys::generate();
        let remote = Keys::generate().public_key();
        let at = Timestamp::from_secs(1_700_000_000);
        let ev = nip46_event(&client, remote, "ct".into(), at).unwrap();
        assert_eq!(ev.kind, Kind::Custom(24133));
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

    #[cfg(all(target_arch = "wasm32", not(feature = "ssr")))]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn wasm_nip46_event_signs_with_browser_clock() {
        let client = Keys::generate();
        let remote = Keys::generate().public_key();
        let ev = nip46_event(&client, remote, "ct".into(), now_timestamp()).unwrap();
        ev.verify().unwrap();
        assert!(ev.created_at.as_secs() > 1_700_000_000);
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
            relay_url: String::new(),
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
