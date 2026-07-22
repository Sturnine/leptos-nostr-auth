use nostr::{FromBech32, Keys, PublicKey, SecretKey};
#[cfg(not(feature = "ssr"))]
use core::fmt::Write;

use crate::types::NostrAuthError;

/// Re-export so storage.rs can use it without circular imports.
pub use crate::types::AuthResult;

// WASM-only imports: js_sys/web_sys APIs, wasm_bindgen FFI, async futures
#[cfg(not(feature = "ssr"))]
use base64::Engine as _;
#[cfg(not(feature = "ssr"))]
use js_sys::{Array, Object, Promise, Reflect, Uint8Array};
#[cfg(not(feature = "ssr"))]
use nostr::JsonUtil;
#[cfg(not(feature = "ssr"))]
use send_wrapper::SendWrapper;
#[cfg(not(feature = "ssr"))]
use std::cell::RefCell;
#[cfg(not(feature = "ssr"))]
use std::collections::HashMap;
#[cfg(not(feature = "ssr"))]
use std::rc::Rc;
#[cfg(not(feature = "ssr"))]
use wasm_bindgen::prelude::*;
#[cfg(not(feature = "ssr"))]
use wasm_bindgen_futures::JsFuture;

// ─────────────────────────────────────────────
//  NIP-07: Browser Extension
// ─────────────────────────────────────────────

// JS bindings for window.nostr (NIP-07) — WASM-only
#[cfg(not(feature = "ssr"))]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "nostr"], js_name = getPublicKey, catch)]
    async fn nostr_get_public_key() -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "nostr"], js_name = signEvent, catch)]
    async fn nostr_sign_event(event: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "nostr", "nip44"], js_name = encrypt, catch)]
    async fn nostr_nip44_encrypt(pubkey: &str, plaintext: &str) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = ["window", "nostr", "nip44"], js_name = decrypt, catch)]
    async fn nostr_nip44_decrypt(pubkey: &str, ciphertext: &str) -> Result<JsValue, JsValue>;
}

/// Handle to an authenticated NIP-07 browser extension session.
#[derive(Clone)]
#[non_exhaustive]
pub struct Nip07Handle {
    /// The authenticated user's public key.
    pub public_key: PublicKey,
}

impl Nip07Handle {
    /// Request the public key from the browser extension.
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when getting the public key fails.
    pub async fn get_public_key() -> Result<Self, NostrAuthError> {
        #[cfg(feature = "ssr")]
        return Err(NostrAuthError::ExtensionNotFound);

        #[cfg(not(feature = "ssr"))]
        {
            let js_pk = nostr_get_public_key()
                .await
                .map_err(|e| NostrAuthError::ExtensionRejected(js_err_msg(&e)))?;
            let hex = js_pk.as_string().ok_or_else(|| {
                NostrAuthError::ExtensionRejected("expected string pubkey".into())
            })?;
            let pk = PublicKey::from_hex(&hex)
                .map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))?;
            Ok(Self { public_key: pk })
        }
    }

    /// Sign a Nostr event via the extension.
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when signing fails.
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
            let event_val = js_sys::JSON::parse(event_json)
                .map_err(|_| NostrAuthError::SigningFailed("invalid event JSON".into()))?;
            let signed = nostr_sign_event(event_val)
                .await
                .map_err(|e| NostrAuthError::SigningFailed(js_err_msg(&e)))?;
            js_sys::JSON::stringify(&signed)
                .map(|s| s.as_string().unwrap_or_default())
                .map_err(|_| {
                    NostrAuthError::SigningFailed("could not stringify signed event".into())
                })
        }
    }

    /// NIP-44 encrypt via extension.
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when nip44 encryption fails.
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
            nostr_nip44_encrypt(recipient_hex, plaintext)
                .await
                .map_err(|e| NostrAuthError::SigningFailed(js_err_msg(&e)))?
                .as_string()
                .ok_or_else(|| NostrAuthError::SigningFailed("expected string ciphertext".into()))
        }
    }

    /// NIP-44 decrypt via extension.
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
            nostr_nip44_decrypt(sender_hex, ciphertext)
                .await
                .map_err(|e| NostrAuthError::SigningFailed(js_err_msg(&e)))?
                .as_string()
                .ok_or_else(|| NostrAuthError::SigningFailed("expected string plaintext".into()))
        }
    }
}

// ─────────────────────────────────────────────
//  NIP-46: Nostr Connect / Bunker
// ─────────────────────────────────────────────

/// Parsed bunker:// URI components — only needed in WASM (all callers are gated).
#[cfg(not(feature = "ssr"))]
struct BunkerUri {
    remote_pubkey_hex: String,
    relay_url: String,
    secret: Option<String>,
}

#[cfg(not(feature = "ssr"))]
fn parse_bunker_uri(uri: &str) -> Result<BunkerUri, NostrAuthError> {
    // Accept both bunker:// and nostrconnect:// schemes
    let stripped = uri
        .strip_prefix("bunker://")
        .or_else(|| uri.strip_prefix("nostrconnect://"))
        .ok_or_else(|| {
            NostrAuthError::InvalidBunkerUri(
                "URI must start with bunker:// or nostrconnect://".into(),
            )
        })?;

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

#[cfg(not(feature = "ssr"))]
fn urlencoding_decode(s: &str) -> String {
    js_sys::decode_uri_component(s).map_or_else(
        |_| s.to_string(),
        |v| v.as_string().unwrap_or_else(|| s.to_string()),
    )
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
#[derive(Clone)]
#[allow(dead_code)] // fields used only in non-ssr code paths
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
    /// so reconnects don't accumulate closures holding client_keys clones.
    #[cfg(not(feature = "ssr"))]
    message_handler: SendWrapper<MessageHandlerSlot>,
    /// Pending RPC callbacks keyed by request ID.
    #[cfg(not(feature = "ssr"))]
    pending: SendWrapper<PendingMap>,
}

impl BunkerSession {
    /// Establish a NIP-46 connection from a `bunker://` or `nostrconnect://` URI.
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when connection fails.
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
            let parsed = parse_bunker_uri(uri)?;

            let remote_pubkey = PublicKey::from_hex(&parsed.remote_pubkey_hex)
                .map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))?;

            // Generate an ephemeral keypair for this client session
            let client_keys = Keys::generate();
            let client_pubkey_hex = client_keys.public_key().to_hex();

            // NIP-46 connect request payload
            let req_id = generate_request_id();
            let params = match &parsed.secret {
                Some(s) => serde_json::json!({
                    "id": req_id,
                    "method": "connect",
                    "params": [client_pubkey_hex, s, "sign_event,get_public_key,nip44_encrypt,nip44_decrypt"]
                }),
                None => serde_json::json!({
                    "id": req_id,
                    "method": "connect",
                    "params": [client_pubkey_hex, "", "sign_event,get_public_key,nip44_encrypt,nip44_decrypt"]
                }),
            };

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
            let event = nostr::EventBuilder::new(nostr::Kind::Custom(24133), encrypted)
                .tag(nostr::Tag::public_key(remote_pubkey))
                .sign_with_keys(&client_keys)
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

            Ok(Self {
                public_key: result_pubkey,
                bunker_uri: uri.to_string(),
                timeout_secs,
                client_keys,
                remote_pubkey,
                relay_url: parsed.relay_url,
                ws: SendWrapper::new(Rc::new(RefCell::new(None))),
                message_handler: SendWrapper::new(Rc::new(RefCell::new(None))),
                pending: SendWrapper::new(Rc::new(RefCell::new(HashMap::new()))),
            })
        }
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
                .map(std::string::ToString::to_string)
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
            v.as_str()
                .map(std::string::ToString::to_string)
                .ok_or_else(|| {
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
            v.as_str()
                .map(std::string::ToString::to_string)
                .ok_or_else(|| {
                    NostrAuthError::SigningFailed("invalid nip44_decrypt response".into())
                })
        }
    }

    /// Ensure the persistent WebSocket is open, reconnecting if necessary.
    /// Returns the WebSocket ready to send messages.
    #[cfg(not(feature = "ssr"))]
    async fn ensure_ws(&self) -> Result<web_sys::WebSocket, NostrAuthError> {
        // Check if we have an open WS already
        if let Some(ws) = self.ws.borrow().as_ref()
            && ws.ready_state() == web_sys::WebSocket::OPEN
        {
            return Ok(ws.clone());
        }

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
        let event = nostr::EventBuilder::new(nostr::Kind::Custom(24133), encrypted)
            .tag(nostr::Tag::public_key(self.remote_pubkey))
            .sign_with_keys(&self.client_keys)
            .map_err(|e| NostrAuthError::SigningFailed(e.to_string()))?;

        // Register a promise in the pending map before sending
        let (response_promise, resolve_fn, reject_fn) = make_rpc_promise();
        let req_id_owned = req_id.to_string();
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

/// Install a persistent `onmessage` handler that decrypts NIP-46 responses and
/// dispatches them to the pending map. The closure is stored in `handler_slot`,
/// which drops (and zeroizes) any previous handler's captured client_keys clone
/// instead of leaking it — important since this runs on every reconnect.
#[cfg(not(feature = "ssr"))]
fn setup_persistent_message_handler(
    ws: &web_sys::WebSocket,
    pending: &PendingMap,
    client_keys: &Keys,
    remote_pubkey: &PublicKey,
    handler_slot: &MessageHandlerSlot,
) {
    let pending_clone = pending.clone();
    let keys_clone = client_keys.clone();
    let remote_pk_clone = *remote_pubkey;
    let remote_hex = remote_pubkey.to_hex();

    let on_message = Closure::<dyn FnMut(_)>::new(move |e: web_sys::MessageEvent| {
        let Some(data) = e.data().as_string() else {
            return;
        };
        let msg: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => return,
        };
        if msg[0].as_str() != Some("EVENT") {
            return;
        }
        let event_obj = &msg[2];
        if event_obj["kind"].as_u64() != Some(24133) {
            return;
        }
        match event_obj["pubkey"].as_str() {
            Some(pk) if pk == remote_hex => {}
            _ => return,
        }
        let ciphertext = match event_obj["content"].as_str() {
            Some(s) => s.to_string(),
            None => return,
        };
        let Ok(plaintext) =
            nostr::nips::nip44::decrypt(keys_clone.secret_key(), &remote_pk_clone, &ciphertext)
        else {
            return;
        };
        let resp: serde_json::Value = match serde_json::from_str(&plaintext) {
            Ok(v) => v,
            Err(_) => return,
        };
        let Some(req_id) = resp["id"].as_str() else {
            return;
        };

        let cb = pending_clone.borrow_mut().remove(req_id);
        if let Some(cb) = cb {
            if let Some(err) = resp["error"].as_str().filter(|s| !s.is_empty()) {
                cb(Err(err.to_string()));
            } else {
                cb(Ok(resp["result"].to_string()));
            }
        }
    });

    ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
    // Replacing the slot drops any previous handler (and its captured client_keys
    // clone) instead of leaking it, so reconnects don't accumulate key material.
    *handler_slot.borrow_mut() = Some(on_message);
}

/// Create a Promise and extract its resolve/reject functions.
#[cfg(not(feature = "ssr"))]
fn make_rpc_promise() -> (Promise, Option<js_sys::Function>, Option<js_sys::Function>) {
    let resolve_cell: Rc<RefCell<Option<js_sys::Function>>> = Rc::new(RefCell::new(None));
    let reject_cell: Rc<RefCell<Option<js_sys::Function>>> = Rc::new(RefCell::new(None));
    let rc = resolve_cell.clone();
    let rj = reject_cell.clone();
    let promise = Promise::new(&mut |resolve, reject| {
        *rc.borrow_mut() = Some(resolve);
        *rj.borrow_mut() = Some(reject);
    });
    let resolve_fn = resolve_cell.borrow().clone();
    let reject_fn = reject_cell.borrow().clone();
    (promise, resolve_fn, reject_fn)
}

/// Create a Promise that rejects with `"timeout"` after `timeout_secs` seconds.
#[cfg(not(feature = "ssr"))]
fn make_timeout_promise(timeout_secs: u32) -> Promise {
    let timeout_ms = f64::from(timeout_secs) * 1000.0;
    Promise::new(&mut |_resolve, reject| {
        let cb = Closure::once(move || {
            let _ = reject.call1(&JsValue::UNDEFINED, &JsValue::from_str("timeout"));
        });
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                timeout_ms as i32,
            )
            .unwrap();
        cb.forget();
    })
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

    let event = nostr::EventBuilder::new(nostr::Kind::Custom(24133), encrypted)
        .tag(nostr::Tag::public_key(remote_pk))
        .sign_with_keys(client_keys)
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
    let remote_pubkey_hex_owned = remote_pubkey_hex.to_string();
    let req_id_owned = req_id.to_string();
    let event_json_owned = event_json.to_string();
    let client_pubkey_hex_owned = client_pubkey_hex.to_string();

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
        let msg: serde_json::Value = match serde_json::from_str(&data) {
            Ok(v) => v,
            Err(_) => return,
        };
        if msg[0].as_str() != Some("EVENT") {
            return;
        }
        let event_obj = &msg[2];
        if event_obj["kind"].as_u64() != Some(24133) {
            return;
        }
        if event_obj["pubkey"].as_str().unwrap_or_default() != remote_pubkey_hex_owned {
            return;
        }
        let ciphertext = match event_obj["content"].as_str() {
            Some(s) => s.to_string(),
            None => return,
        };
        let Ok(remote_pk) = PublicKey::from_hex(&remote_pubkey_hex_owned) else {
            return;
        };
        let Ok(plaintext) =
            nostr::nips::nip44::decrypt(client_keys_clone.secret_key(), &remote_pk, &ciphertext)
        else {
            return;
        };
        let resp: serde_json::Value = match serde_json::from_str(&plaintext) {
            Ok(v) => v,
            Err(_) => return,
        };
        if resp["id"].as_str() != Some(&req_id_owned) {
            return;
        }
        if let Some(err) = resp["error"].as_str().filter(|s| !s.is_empty()) {
            if let Some(f) = &reject_for_msg {
                let _ = f.call1(&JsValue::UNDEFINED, &JsValue::from_str(err));
            }
            return;
        }
        let result = resp["result"].to_string();
        if let Some(f) = &resolve_for_msg {
            let _ = f.call1(&JsValue::UNDEFINED, &JsValue::from_str(&result));
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

// ─────────────────────────────────────────────
//  Passkey — WebAuthn PRF (Roadflare pattern)
// ─────────────────────────────────────────────

/// Fixed PRF salt (same as Roadflare iOS: `SHA256("nostr-key-v1")` raw bytes passed as salt).
/// This constant is the UTF-8 bytes of "nostr-key-v1" — WebAuthn PRF hashes them internally.
#[cfg(not(feature = "ssr"))]
const PRF_SALT: &[u8] = b"nostr-key-v1";

/// An active passkey session. The secret key is in-memory only; derived anew on each login.
///
/// The passkey (and by extension, your Nostr identity) syncs via iCloud Keychain on Apple
/// devices, or Google Password Manager / Windows Hello on other platforms.
#[derive(Clone)]
pub struct PasskeySession {
    /// The authenticated user's public key.
    pub public_key: PublicKey,
    /// In-memory-only secp256k1 secret key derived from the WebAuthn PRF output.
    secret_key: SecretKey,
    /// base64url-encoded credential ID — stored in `PersistedSession` for restore
    pub credential_id: Vec<u8>,
}

impl PasskeySession {
    /// Create a brand-new Nostr identity backed by a passkey.
    ///
    /// On macOS/iOS: triggers Touch ID / Face ID sheet. The resulting passkey
    /// syncs via iCloud Keychain to all the user's Apple devices.
    /// # Errors
    ///
    /// Returns an error if the passkey creation fails.
    pub async fn create(rp_id: &str, rp_name: &str) -> Result<Self, NostrAuthError> {
        #[cfg(feature = "ssr")]
        {
            let _ = (rp_id, rp_name);
            Err(NostrAuthError::PasskeyFailed(
                "not available on server".into(),
            ))
        }

        #[cfg(not(feature = "ssr"))]
        {
            let window = web_sys::window()
                .ok_or_else(|| NostrAuthError::PasskeyFailed("no window object".into()))?;
            let credentials = window.navigator().credentials();

            // Build a random user ID (not linked to the Nostr key — just for WebAuthn bookkeeping)
            let user_id = random_bytes(16);
            let user_id_u8 = Uint8Array::from(user_id.as_slice());

            // Build the creation options object using js-sys Reflect
            let options = Object::new();
            let pk_opts = Object::new();

            // rp
            let rp = Object::new();
            set_str(&rp, "id", rp_id);
            set_str(&rp, "name", rp_name);
            set(&pk_opts, "rp", &rp);

            // user
            let user = Object::new();
            Reflect::set(&user, &"id".into(), &user_id_u8).unwrap();
            set_str(&user, "name", "nostr");
            set_str(&user, "displayName", "Nostr Identity");
            set(&pk_opts, "user", &user);

            // challenge
            let challenge = Uint8Array::from(random_bytes(32).as_slice());
            set(&pk_opts, "challenge", &challenge);

            // pubKeyCredParams: ES256 (-7)
            let param = Object::new();
            set_str(&param, "type", "public-key");
            Reflect::set(&param, &"alg".into(), &(-7_i32).into()).unwrap();
            let params = Array::of1(&param);
            set(&pk_opts, "pubKeyCredParams", &params);

            // authenticatorSelection: prefer platform, resident key required
            let auth_sel = Object::new();
            set_str(&auth_sel, "authenticatorAttachment", "platform");
            set_str(&auth_sel, "residentKey", "required");
            set_str(&auth_sel, "userVerification", "required");
            set(&pk_opts, "authenticatorSelection", &auth_sel);

            // extensions: prf with our fixed salt
            let extensions = Object::new();
            let prf = Object::new();
            let prf_eval = Object::new();
            let salt_u8 = Uint8Array::from(PRF_SALT);
            Reflect::set(&prf_eval, &"first".into(), &salt_u8).unwrap();
            set(&prf, "eval", &prf_eval);
            set(&extensions, "prf", &prf);
            set(&pk_opts, "extensions", &extensions);

            set(&options, "publicKey", &pk_opts);

            let promise = credentials
                .create_with_options(&options.unchecked_into())
                .map_err(|e| NostrAuthError::PasskeyFailed(format!("{e:?}")))?;

            let credential = JsFuture::from(promise).await.map_err(|e| {
                web_sys::console::error_1(&e);
                NostrAuthError::PasskeyFailed(js_err_msg(&e))
            })?;

            Self::derive_from_credential(&credential)
        }
    }

    /// Authenticate with an existing passkey using its credential ID.
    ///
    /// On macOS/iOS: triggers Touch ID / Face ID sheet.
    /// The same passkey + same PRF salt always produces the same Nostr key (deterministic).
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when passkey authentication fails.
    pub async fn authenticate(credential_id: Vec<u8>) -> Result<Self, NostrAuthError> {
        #[cfg(feature = "ssr")]
        {
            let _ = credential_id;
            Err(NostrAuthError::PasskeyFailed(
                "not available on server".into(),
            ))
        }

        #[cfg(not(feature = "ssr"))]
        {
            let window = web_sys::window()
                .ok_or_else(|| NostrAuthError::PasskeyFailed("no window object".into()))?;
            let credentials = window.navigator().credentials();

            let options = Object::new();
            let pk_opts = Object::new();

            let challenge = Uint8Array::from(random_bytes(32).as_slice());
            set(&pk_opts, "challenge", &challenge);
            set_str(&pk_opts, "userVerification", "required");

            let extensions = Object::new();
            let prf = Object::new();

            // Always include eval — required by browsers that don't support evalByCredential
            // (Safari ≤16.x, older Firefox). Same salt → same PRF output as evalByCredential.
            let prf_eval = Object::new();
            let salt_u8 = Uint8Array::from(PRF_SALT);
            Reflect::set(&prf_eval, &"first".into(), &salt_u8).unwrap();
            set(&prf, "eval", &prf_eval);

            if !credential_id.is_empty() {
                // Restrict assertion to the stored credential
                let cred_descriptor = Object::new();
                set_str(&cred_descriptor, "type", "public-key");
                let cred_id_u8 = Uint8Array::from(credential_id.as_slice());
                set(&cred_descriptor, "id", &cred_id_u8);
                let allow_creds = Array::of1(&cred_descriptor);
                set(&pk_opts, "allowCredentials", &allow_creds);

                // evalByCredential for spec-compliant browsers that prefer it over eval
                let cred_id_b64 =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&credential_id);
                let eval_by_cred = Object::new();
                let prf_eval_ebc = Object::new();
                let salt_u8_ebc = Uint8Array::from(PRF_SALT);
                Reflect::set(&prf_eval_ebc, &"first".into(), &salt_u8_ebc).unwrap();
                Reflect::set(&eval_by_cred, &cred_id_b64.into(), &prf_eval_ebc).unwrap();
                set(&prf, "evalByCredential", &eval_by_cred);
            }

            set(&extensions, "prf", &prf);
            set(&pk_opts, "extensions", &extensions);

            set(&options, "publicKey", &pk_opts);

            let promise = credentials
                .get_with_options(&options.unchecked_into())
                .map_err(|e| NostrAuthError::PasskeyFailed(format!("{e:?}")))?;

            let credential = JsFuture::from(promise).await.map_err(|e| {
                web_sys::console::error_1(&e);
                NostrAuthError::PasskeyFailed(js_err_msg(&e))
            })?;

            Self::derive_from_credential(&credential)
        }
    }

    /// Derive the Nostr keypair from a WebAuthn credential's PRF output.
    ///
    /// Flow (mirrors Roadflare iOS):
    ///   PRF output (32 bytes) → SHA-256 → secp256k1 private key
    #[cfg(not(feature = "ssr"))]
    fn derive_from_credential(credential: &JsValue) -> Result<Self, NostrAuthError> {
        // Extract credential ID
        let raw_id = Reflect::get(credential, &"rawId".into())
            .map_err(|_| NostrAuthError::PasskeyFailed("no rawId".into()))?;
        let cred_id_u8 = Uint8Array::new(&raw_id);
        let credential_id = cred_id_u8.to_vec();

        // Navigate: credential.getClientExtensionResults().prf.results.first
        let get_exts = Reflect::get(credential, &"getClientExtensionResults".into())
            .and_then(|f| {
                f.dyn_ref::<js_sys::Function>()
                    .ok_or(JsValue::UNDEFINED)?
                    .call0(credential)
            })
            .map_err(|_| {
                NostrAuthError::PasskeyFailed("getClientExtensionResults failed".into())
            })?;

        let prf_results = Reflect::get(&get_exts, &"prf".into())
            .and_then(|p| Reflect::get(&p, &"results".into()))
            .map_err(|_| NostrAuthError::PasskeyNotSupported)?;

        if prf_results.is_undefined() || prf_results.is_null() {
            return Err(NostrAuthError::PasskeyNotSupported);
        }

        let first = Reflect::get(&prf_results, &"first".into())
            .map_err(|_| NostrAuthError::PasskeyFailed("no PRF first output".into()))?;

        let prf_bytes = Uint8Array::new(&first).to_vec();

        if prf_bytes.len() != 32 {
            return Err(NostrAuthError::PasskeyFailed(format!(
                "PRF output must be 32 bytes, got {}",
                prf_bytes.len()
            )));
        }

        // SHA-256 of the PRF output → secp256k1 private key (deterministic, Roadflare pattern)
        let digest = sha256_bytes(&prf_bytes);

        let secret_key = SecretKey::from_slice(&digest)
            .map_err(|e| NostrAuthError::PasskeyFailed(e.to_string()))?;

        let keys = Keys::new(secret_key.clone());
        let public_key = keys.public_key();

        Ok(Self {
            public_key,
            secret_key,
            credential_id,
        })
    }

    /// Sign a Nostr event using the in-memory derived key.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        let unsigned: nostr::UnsignedEvent = serde_json::from_str(event_json)
            .map_err(|e| NostrAuthError::Serialization(e.to_string()))?;
        let keys = Keys::new(self.secret_key.clone());
        let signed = unsigned
            .sign_with_keys(&keys)
            .map_err(|e| NostrAuthError::SigningFailed(e.to_string()))?;
        serde_json::to_string(&signed).map_err(|e| NostrAuthError::Serialization(e.to_string()))
    }
}

/// Compute SHA-256 synchronously (using the `nostr` crate's transitive dep).
#[cfg(not(feature = "ssr"))]
fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    use nostr::hashes::{Hash, sha256};
    let mut engine = sha256::Hash::engine();
    nostr::hashes::HashEngine::input(&mut engine, input);
    let hash = sha256::Hash::from_engine(engine);
    hash.to_byte_array()
}

#[cfg(not(feature = "ssr"))]
#[allow(clippy::cast_possible_truncation)]
fn random_bytes(len: usize) -> Vec<u8> {
    let window = web_sys::window().unwrap();
    let crypto = window.crypto().unwrap();
    let mut buf = vec![0u8; len];
    let u8arr = Uint8Array::new_with_length(len as u32);
    crypto
        .get_random_values_with_array_buffer_view(&u8arr)
        .unwrap();
    u8arr.copy_to(&mut buf);
    buf
}

/// Extract a human-readable message from any JS error value.
#[cfg(not(feature = "ssr"))]
fn js_err_msg(e: &JsValue) -> String {
    e.as_string()
        .or_else(|| {
            Reflect::get(e, &"message".into())
                .ok()
                .and_then(|v| v.as_string())
        })
        .unwrap_or_else(|| format!("{e:?}"))
}

#[cfg(not(feature = "ssr"))]
fn set(obj: &Object, key: &str, val: &JsValue) {
    Reflect::set(obj, &key.into(), val).unwrap();
}

#[cfg(not(feature = "ssr"))]
fn set_str(obj: &Object, key: &str, val: &str) {
    Reflect::set(obj, &key.into(), &JsValue::from_str(val)).unwrap();
}

// ─────────────────────────────────────────────
//  Read-Only
// ─────────────────────────────────────────────

/// Read-only access — public key only, no signing capability.
#[derive(Clone)]
#[non_exhaustive]
pub struct ReadOnlyHandle {
    /// The authenticated user's public key.
    pub public_key: PublicKey,
}

impl core::str::FromStr for ReadOnlyHandle {
    type Err = NostrAuthError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        if let Ok(pk) = PublicKey::from_hex(input) {
            return Ok(Self { public_key: pk });
        }
        if let Ok(pk) = PublicKey::from_bech32(input) {
            return Ok(Self { public_key: pk });
        }
        if input.starts_with("nprofile")
            && let Ok(profile) = nostr::nips::nip19::Nip19Profile::from_bech32(input)
        {
            return Ok(Self {
                public_key: profile.public_key,
            });
        }
        Err(NostrAuthError::InvalidPublicKey(
            "Expected npub1..., nprofile1..., or 64-char hex public key".into(),
        ))
    }
}

// ─────────────────────────────────────────────
//  RawKeySession — ncryptsec (NIP-49) + raw nsec
// ─────────────────────────────────────────────

/// In-memory raw key session. Used for NIP-49 ncryptsec and (feature-gated) raw nsec paste.
///
/// The private key is held in memory for the lifetime of this struct. Each clone holds an
/// independent copy — avoid unnecessary cloning. The nostr crate's `SecretKey` implements
/// `ZeroizeOnDrop` internally, so each copy is zeroed when dropped.
#[derive(Clone)]
pub struct RawKeySession {
    /// The authenticated user's public key.
    pub public_key: PublicKey,
    /// In-memory secp256k1 secret key; zeroed on drop via `ZeroizeOnDrop`.
    secret_key: SecretKey,
}

impl RawKeySession {
    /// Decrypt a NIP-49 `ncryptsec1...` string with a password.
    ///
    /// scrypt derivation is CPU-intensive — call this inside `spawn_local` to avoid
    /// blocking the browser's main thread while the spinner shows.
    ///
    /// # Errors
    ///
    /// Returns an error when decrypting fails.
    pub fn from_ncryptsec(ncryptsec: &str, password: &str) -> Result<Self, NostrAuthError> {
        let encrypted = nostr::nips::nip49::EncryptedSecretKey::from_bech32(ncryptsec)
            .map_err(|e| NostrAuthError::InvalidNcryptsec(e.to_string()))?;

        let secret_key = encrypted.decrypt(password).map_err(|e| {
            if matches!(e, nostr::nips::nip49::Error::ChaCha20Poly1305(_)) {
                NostrAuthError::WrongPassword
            } else {
                NostrAuthError::InvalidNcryptsec(e.to_string())
            }
        })?;

        let keys = Keys::new(secret_key.clone());
        Ok(Self {
            public_key: keys.public_key(),
            secret_key,
        })
    }

    /// Parse a raw `nsec1...` bech32 or 64-char hex private key.
    ///
    /// Only available with the `insecure_nsec_input` feature flag.
    ///
    /// # Errors
    ///
    /// Returns an error when parsing nsec fails.
    #[cfg(feature = "insecure_nsec_input")]
    pub fn from_nsec_or_hex(input: &str) -> Result<Self, NostrAuthError> {
        let input = input.trim();
        let secret_key = if let Ok(sk) = SecretKey::from_bech32(input) {
            sk
        } else if let Ok(sk) = SecretKey::from_hex(input) {
            sk
        } else {
            return Err(NostrAuthError::InvalidSecretKey(
                "Expected nsec1... (bech32) or 64-char hex private key".into(),
            ));
        };
        let keys = Keys::new(secret_key.clone());
        Ok(Self {
            public_key: keys.public_key(),
            secret_key,
        })
    }

    /// Sign a Nostr event with the in-memory key.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        let unsigned: nostr::UnsignedEvent = serde_json::from_str(event_json)
            .map_err(|e| NostrAuthError::Serialization(e.to_string()))?;
        let keys = Keys::new(self.secret_key.clone());
        let signed = unsigned
            .sign_with_keys(&keys)
            .map_err(|e| NostrAuthError::SigningFailed(e.to_string()))?;
        serde_json::to_string(&signed).map_err(|e| NostrAuthError::Serialization(e.to_string()))
    }
}
