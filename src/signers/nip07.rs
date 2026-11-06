use nostr::key::PublicKey;

use crate::types::NostrAuthError;

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
    /// Returns [`NostrAuthError::ExtensionNotFound`] when called with SSR features, or when
    /// `window.nostr` or `getPublicKey` is missing. Returns
    /// [`NostrAuthError::ExtensionRejected`] when a present method refuses or throws.
    pub async fn get_public_key() -> Result<Self, NostrAuthError> {
        imp::get_public_key().await
    }

    /// Sign a Nostr event via the extension. The request and the returned event follow the contract
    /// on [`crate::AuthResult::sign_event`], so an extension on another account fails after its own
    /// prompt.
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when signing fails.
    /// [`NostrAuthError::SignerKeyMismatch`] means the extension signed with another key, and
    /// [`NostrAuthError::ExtensionNotFound`] means `window.nostr` or `signEvent` is missing.
    pub async fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        imp::sign_event(self, event_json).await
    }

    /// NIP-44 encrypt via extension, after checking the extension is still on this session's
    /// account. An account switch between that check and the call is not detected, because a
    /// NIP-44 result has nothing to verify.
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when nip44 encryption fails.
    /// [`NostrAuthError::SignerKeyMismatch`] means the extension is on another account. The account
    /// check can also return [`NostrAuthError::ExtensionRejected`] or
    /// [`NostrAuthError::InvalidPublicKey`], and a missing `nip44` is
    /// [`NostrAuthError::ExtensionNotFound`].
    pub async fn nip44_encrypt(
        &self,
        recipient_hex: &str,
        plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        imp::nip44_encrypt(self, recipient_hex, plaintext).await
    }

    /// NIP-44 decrypt via extension, after the same account check as
    /// [`nip44_encrypt`](Self::nip44_encrypt).
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when nip44 decryption fails, and the same
    /// account-check errors as [`nip44_encrypt`](Self::nip44_encrypt).
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
    use js_sys::Reflect;
    use nostr::key::PublicKey;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;

    use super::Nip07Handle;
    use crate::signers::browser::make_rpc_promise;
    use crate::signers::event_contract::{checked_event, prepare};
    use crate::types::NostrAuthError;

    /// Text for a rejection that carries no readable message.
    const STATIC_REJECTION: &str = "extension rejected the request";

    // Not `async` imports: wasm-bindgen does not take the exception an `async` catch import stored,
    // so a throw would leave a stale exception and `.then` called on `undefined`.
    #[wasm_bindgen]
    extern "C" {
        #[wasm_bindgen(js_namespace = ["window", "nostr"], js_name = getPublicKey, catch)]
        fn nostr_get_public_key() -> Result<JsValue, JsValue>;

        #[wasm_bindgen(js_namespace = ["window", "nostr"], js_name = signEvent, catch)]
        fn nostr_sign_event(event: &JsValue) -> Result<JsValue, JsValue>;

        #[wasm_bindgen(js_namespace = ["window", "nostr", "nip44"], js_name = encrypt, catch)]
        fn nostr_nip44_encrypt(pubkey: &str, plaintext: &str) -> Result<JsValue, JsValue>;

        #[wasm_bindgen(js_namespace = ["window", "nostr", "nip44"], js_name = decrypt, catch)]
        fn nostr_nip44_decrypt(pubkey: &str, ciphertext: &str) -> Result<JsValue, JsValue>;
    }

    /// Whether the method at `path` from the global object exists and can be called. Reads through
    /// a catch import, so a throwing getter or Proxy trap reads as absent.
    fn method_is_callable(path: &[&str]) -> bool {
        let mut current: JsValue = js_sys::global().into();
        for step in path {
            match Reflect::get(&current, &JsValue::from_str(step)) {
                Ok(next) if !next.is_null() && !next.is_undefined() => current = next,
                _ => return false,
            }
        }
        current.is_function()
    }

    /// What a throw or rejection says about itself. `js_err_msg` would fall back to the Debug form,
    /// printing an object an extension rejected with, possibly a full event.
    fn rejection_text(value: &JsValue) -> String {
        value
            .as_string()
            .or_else(|| {
                Reflect::get(value, &"message".into())
                    .ok()
                    .and_then(|m| m.as_string())
            })
            .unwrap_or_else(|| STATIC_REJECTION.to_owned())
    }

    /// Settle what an extension call returned. A signer can return a non-Promise or a Promise with
    /// its own `then`, and neither `Promise::resolve` nor `JsFuture::from` guards the calls they
    /// make on it. A resolve function reads `then` under its own catch and runs it in a later job,
    /// so `JsFuture` only ever sees a fresh native promise.
    async fn settle(
        called: Result<JsValue, JsValue>,
        path: &[&str],
        refused: fn(String) -> NostrAuthError,
    ) -> Result<JsValue, NostrAuthError> {
        let value = match called {
            Ok(v) => v,
            Err(thrown) if method_is_callable(path) => {
                return Err(refused(rejection_text(&thrown)));
            }
            Err(_) => return Err(NostrAuthError::ExtensionNotFound),
        };
        let (promise, resolve, _) = make_rpc_promise();
        let _ = resolve.call1(&JsValue::UNDEFINED, &value);
        JsFuture::from(promise)
            .await
            .map_err(|e| refused(rejection_text(&e)))
    }

    /// Request the public key from the extension.
    pub(super) async fn get_public_key() -> Result<Nip07Handle, NostrAuthError> {
        let js_pk = settle(
            nostr_get_public_key(),
            &["window", "nostr", "getPublicKey"],
            NostrAuthError::ExtensionRejected,
        )
        .await?;
        let hex = js_pk
            .as_string()
            .ok_or_else(|| NostrAuthError::ExtensionRejected("expected string pubkey".into()))?;
        let pk = PublicKey::from_hex(&hex)
            .map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))?;
        Ok(Nip07Handle { public_key: pk })
    }

    /// Sign an event through the extension. A value that cannot be stringified has no text, which
    /// `checked_event` refuses without quoting anything from JS.
    pub(super) async fn sign_event(
        handle: &Nip07Handle,
        event_json: &str,
    ) -> Result<String, NostrAuthError> {
        let request = prepare(event_json, handle.public_key)?;
        let event = js_sys::JSON::parse(&request.as_json())
            .map_err(|e| NostrAuthError::Serialization(rejection_text(&e)))?;
        let signed = settle(
            nostr_sign_event(&event),
            &["window", "nostr", "signEvent"],
            NostrAuthError::SigningFailed,
        )
        .await?;
        let returned = js_sys::JSON::stringify(&signed)
            .ok()
            .and_then(|s| s.as_string())
            .unwrap_or_default();
        checked_event(&request, handle.public_key, &returned)
    }

    /// A NIP-44 result has nothing to verify, so the extension's current account is checked first.
    async fn ensure_account(handle: &Nip07Handle) -> Result<(), NostrAuthError> {
        if get_public_key().await?.public_key == handle.public_key {
            Ok(())
        } else {
            Err(NostrAuthError::SignerKeyMismatch)
        }
    }

    /// NIP-44 encrypt through the extension.
    pub(super) async fn nip44_encrypt(
        handle: &Nip07Handle,
        recipient_hex: &str,
        plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        ensure_account(handle).await?;
        settle(
            nostr_nip44_encrypt(recipient_hex, plaintext),
            &["window", "nostr", "nip44", "encrypt"],
            NostrAuthError::SigningFailed,
        )
        .await?
        .as_string()
        .ok_or_else(|| NostrAuthError::SigningFailed("expected string ciphertext".into()))
    }

    /// NIP-44 decrypt through the extension.
    pub(super) async fn nip44_decrypt(
        handle: &Nip07Handle,
        sender_hex: &str,
        ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        ensure_account(handle).await?;
        settle(
            nostr_nip44_decrypt(sender_hex, ciphertext),
            &["window", "nostr", "nip44", "decrypt"],
            NostrAuthError::SigningFailed,
        )
        .await?
        .as_string()
        .ok_or_else(|| NostrAuthError::SigningFailed("expected string plaintext".into()))
    }
}

/// Server stubs.
#[cfg(feature = "ssr")]
mod imp {
    use super::Nip07Handle;
    use crate::signers::NOT_ON_SERVER;
    use crate::types::NostrAuthError;

    /// Server stub for `get_public_key`.
    pub(super) async fn get_public_key() -> Result<Nip07Handle, NostrAuthError> {
        Err(NostrAuthError::ExtensionNotFound)
    }

    /// Server stub for `sign_event`.
    pub(super) async fn sign_event(
        _handle: &Nip07Handle,
        _event_json: &str,
    ) -> Result<String, NostrAuthError> {
        Err(NostrAuthError::SigningFailed(NOT_ON_SERVER.into()))
    }

    /// Server stub for `nip44_encrypt`.
    pub(super) async fn nip44_encrypt(
        _handle: &Nip07Handle,
        _recipient_hex: &str,
        _plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        Err(NostrAuthError::SigningFailed(NOT_ON_SERVER.into()))
    }

    /// Server stub for `nip44_decrypt`.
    pub(super) async fn nip44_decrypt(
        _handle: &Nip07Handle,
        _sender_hex: &str,
        _ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        Err(NostrAuthError::SigningFailed(NOT_ON_SERVER.into()))
    }
}

#[cfg(test)]
#[cfg(feature = "ssr")]
mod server_tests {
    use super::super::server_tests::{ready, text};
    use super::*;
    use nostr::key::Keys;

    #[test]
    fn nip07_server_stubs() {
        let h = Nip07Handle {
            public_key: Keys::generate().public_key(),
        };
        assert_eq!(
            text(ready(Nip07Handle::get_public_key())),
            "Browser extension (window.nostr) not found"
        );
        let want = "Signing failed: not available on server";
        assert_eq!(text(ready(h.sign_event("{}"))), want);
        assert_eq!(text(ready(h.nip44_encrypt("a", "b"))), want);
        assert_eq!(text(ready(h.nip44_decrypt("a", "b"))), want);
    }
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
#[cfg(not(feature = "ssr"))]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    const INVALID: &str = "signer returned an invalid event";
    const STATIC_TEXT: &str = "extension rejected the request";

    fn shim(src: &str) {
        js_sys::eval(src).unwrap();
    }

    fn count(name: &str) -> f64 {
        js_sys::eval(&format!("globalThis.__n.{name}"))
            .unwrap()
            .as_f64()
            .unwrap()
    }

    fn session() -> (nostr::key::Keys, Nip07Handle) {
        let keys = nostr::key::Keys::generate();
        let handle = Nip07Handle {
            public_key: keys.public_key(),
        };
        (keys, handle)
    }

    fn signed_json(keys: &nostr::key::Keys) -> String {
        use crate::signers::signer_traits::tests::unsigned;
        use nostr::event::FinalizeEvent;
        unsigned(keys.public_key())
            .finalize(keys)
            .unwrap()
            .as_json()
    }

    fn request(keys: &nostr::key::Keys) -> String {
        crate::signers::signer_traits::tests::unsigned(keys.public_key()).as_json()
    }

    fn sign_shim(body: &str) {
        shim(&format!(
            "globalThis.__n = {{ sign: 0 }}; globalThis.window = {{ nostr: {{ signEvent: function (e) {{ globalThis.__n.sign += 1; {body} }} }} }};"
        ));
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "callers pass the awaited result inline"
    )]
    fn assert_signing_failed(result: Result<String, NostrAuthError>, text: &str) {
        assert!(
            matches!(&result, Err(NostrAuthError::SigningFailed(m)) if m == text),
            "{result:?}"
        );
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "callers pass the awaited result inline"
    )]
    fn assert_not_found<T: core::fmt::Debug>(result: Result<T, NostrAuthError>) {
        assert!(
            matches!(result, Err(NostrAuthError::ExtensionNotFound)),
            "{result:?}"
        );
    }

    #[wasm_bindgen_test]
    async fn nip07_calls_reach_window_nostr() {
        let (keys, _) = session();
        let want = signed_json(&keys);
        shim(&format!(
            r#"globalThis.window = {{ nostr: {{
                getPublicKey: async () => "{}",
                signEvent: async () => ({}),
                nip44: {{
                    encrypt: async (pk, pt) => "enc:" + pk + ":" + pt,
                    decrypt: async (pk, ct) => "dec:" + pk + ":" + ct,
                }},
            }} }};"#,
            keys.public_key().to_hex(),
            want
        ));
        let h = Nip07Handle::get_public_key().await.unwrap();
        assert_eq!(h.public_key, keys.public_key());
        let signed = h.sign_event(&request(&keys)).await.unwrap();
        assert_eq!(signed, want);
        assert_eq!(h.nip44_encrypt("pk", "hi").await.unwrap(), "enc:pk:hi");
        assert_eq!(h.nip44_decrypt("pk", "ct").await.unwrap(), "dec:pk:ct");
    }

    async fn assert_all_not_found(keys: &nostr::key::Keys, h: &Nip07Handle) {
        assert_not_found(h.sign_event(&request(keys)).await);
        assert_not_found(Nip07Handle::get_public_key().await.map(|_| ()));
        assert_not_found(h.nip44_encrypt("pk", "x").await);
        assert_not_found(h.nip44_decrypt("pk", "x").await);
    }

    #[wasm_bindgen_test]
    async fn no_window_is_typed() {
        let (keys, h) = session();
        shim("delete globalThis.window;");
        assert_all_not_found(&keys, &h).await;
        sign_shim(&format!("return {};", signed_json(&keys)));
        h.sign_event(&request(&keys)).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn no_nostr_is_typed() {
        let (keys, h) = session();
        shim("globalThis.window = {};");
        assert_all_not_found(&keys, &h).await;
        sign_shim(&format!("return {};", signed_json(&keys)));
        h.sign_event(&request(&keys)).await.unwrap();
    }

    #[wasm_bindgen_test]
    async fn sync_throw_is_a_rejection() {
        let (keys, h) = session();
        let thrown = "throw new Error('denied');";
        sign_shim(thrown);
        assert_signing_failed(h.sign_event(&request(&keys)).await, "denied");
        assert_eq!(count("sign"), 1.0);
        js_sys::JSON::parse("1").unwrap();

        shim(
            "globalThis.__n = { get: 0 }; globalThis.window = { nostr: { getPublicKey() { globalThis.__n.get += 1; throw new Error('denied'); } } };",
        );
        let got = Nip07Handle::get_public_key().await.map(|_| ());
        assert!(
            matches!(&got, Err(NostrAuthError::ExtensionRejected(m)) if m == "denied"),
            "{got:?}"
        );
        assert_eq!(count("get"), 1.0);
        js_sys::JSON::parse("1").unwrap();

        shim(&format!(
            "globalThis.__n = {{ enc: 0, dec: 0 }}; globalThis.window = {{ nostr: {{ getPublicKey: async () => '{}', nip44: {{ encrypt() {{ globalThis.__n.enc += 1; throw new Error('denied'); }}, decrypt() {{ globalThis.__n.dec += 1; throw new Error('denied'); }} }} }} }};",
            keys.public_key().to_hex()
        ));
        assert_signing_failed(h.nip44_encrypt("pk", "x").await, "denied");
        assert_eq!(count("enc"), 1.0);
        js_sys::JSON::parse("1").unwrap();
        assert_signing_failed(h.nip44_decrypt("pk", "x").await, "denied");
        assert_eq!(count("dec"), 1.0);
        js_sys::JSON::parse("1").unwrap();
    }

    #[wasm_bindgen_test]
    async fn sync_throw_object_is_not_dumped() {
        let (keys, h) = session();
        for body in [
            "throw { SENTINEL: 'SENTINEL' };",
            "throw { get message() { throw 1; }, SENTINEL: 'SENTINEL' };",
        ] {
            sign_shim(body);
            assert_signing_failed(h.sign_event(&request(&keys)).await, STATIC_TEXT);
        }
    }

    #[wasm_bindgen_test]
    async fn missing_method_is_not_found() {
        let (keys, h) = session();
        let key = keys.public_key().to_hex();
        shim(&format!(
            "globalThis.window = {{ nostr: {{ getPublicKey: async () => '{key}' }} }};"
        ));
        assert_not_found(h.sign_event(&request(&keys)).await);
        shim("globalThis.window = { nostr: { signEvent: 5 } };");
        assert_not_found(h.sign_event(&request(&keys)).await);
        shim(&format!(
            "globalThis.window = {{ nostr: {{ getPublicKey: async () => '{key}' }} }};"
        ));
        assert_not_found(h.nip44_encrypt("pk", "x").await);
        assert_not_found(h.nip44_decrypt("pk", "x").await);
        shim(&format!(
            "globalThis.window = {{ nostr: {{ getPublicKey: async () => '{key}', nip44: {{}} }} }};"
        ));
        assert_not_found(h.nip44_encrypt("pk", "x").await);
        assert_not_found(h.nip44_decrypt("pk", "x").await);
        shim("globalThis.window = { get nostr() { throw new Error('SENTINEL'); } };");
        assert_not_found(h.sign_event(&request(&keys)).await);
        assert_not_found(Nip07Handle::get_public_key().await.map(|_| ()));
    }

    #[wasm_bindgen_test]
    async fn non_promise_return_is_judged() {
        let (keys, h) = session();
        let want = signed_json(&keys);
        sign_shim(&format!("return {want};"));
        assert_eq!(h.sign_event(&request(&keys)).await.unwrap(), want);
        sign_shim("return undefined;");
        assert_signing_failed(h.sign_event(&request(&keys)).await, INVALID);
    }

    #[wasm_bindgen_test]
    async fn throwing_then_is_a_rejection() {
        let (keys, h) = session();
        sign_shim("return { get then() { throw 1; } };");
        assert_signing_failed(h.sign_event(&request(&keys)).await, STATIC_TEXT);
        sign_shim("const p = Promise.resolve(); p.then = function () { throw 1; }; return p;");
        assert_signing_failed(h.sign_event(&request(&keys)).await, STATIC_TEXT);
        let want = signed_json(&keys);
        sign_shim(&format!(
            "const p = new Promise(() => {{}}); p.then = function (res) {{ res({want}); }}; return p;"
        ));
        assert_eq!(h.sign_event(&request(&keys)).await.unwrap(), want);
        sign_shim(
            "const p = Promise.resolve(); Object.defineProperty(p, 'constructor', { get() { throw 1; } }); return p;",
        );
        assert_signing_failed(h.sign_event(&request(&keys)).await, STATIC_TEXT);
    }

    #[wasm_bindgen_test]
    async fn hostile_values() {
        let (keys, h) = session();
        for body in [
            "const a = {}; a.SENTINEL = a; return a;",
            "return { SENTINEL: 1n };",
            "return { toJSON() { throw new Error('SENTINEL'); } };",
        ] {
            sign_shim(body);
            assert_signing_failed(h.sign_event(&request(&keys)).await, INVALID);
        }
        sign_shim("return Promise.reject({ get message() { throw 1; } });");
        assert_signing_failed(h.sign_event(&request(&keys)).await, STATIC_TEXT);
    }

    #[wasm_bindgen_test]
    async fn empty_and_null_direct() {
        let (keys, h) = session();
        for body in [
            "return Promise.resolve(undefined);",
            "return Promise.resolve(null);",
        ] {
            sign_shim(body);
            assert_signing_failed(h.sign_event(&request(&keys)).await, INVALID);
        }
    }

    #[wasm_bindgen_test]
    async fn rejection_object_is_not_dumped() {
        let (keys, h) = session();
        sign_shim("return Promise.reject({ SENTINEL: 'SENTINEL' });");
        assert_signing_failed(h.sign_event(&request(&keys)).await, STATIC_TEXT);
    }

    #[wasm_bindgen_test]
    async fn other_account_is_typed() {
        use crate::signers::signer_traits::tests::unsigned;
        use core::error::Error as _;
        use nostr::error::ErrorKind;
        use nostr::event::{AsyncSignEvent, FinalizeEventAsync};
        let (keys, auth) = extension();
        let other = nostr::key::Keys::generate();
        sign_shim(&format!("return {};", signed_json(&other)));
        let input = unsigned(keys.public_key());
        let wrapped = input.clone().finalize_async(&auth).await.unwrap_err();
        assert_eq!(wrapped.kind(), ErrorKind::Other);
        let source = wrapped
            .source()
            .and_then(|s| s.downcast_ref::<NostrAuthError>());
        assert!(matches!(source, Some(NostrAuthError::SignerKeyMismatch)));
        let direct = auth.sign_event(&input.as_json()).await;
        assert!(matches!(direct, Err(NostrAuthError::SignerKeyMismatch)));
        let traited = auth.sign_event_async(input).await;
        assert!(matches!(traited, Err(NostrAuthError::SignerKeyMismatch)));
    }

    #[wasm_bindgen_test]
    async fn differing_request_not_sent() {
        let (keys, h) = session();
        let other = nostr::key::Keys::generate();
        sign_shim("return null;");
        let wrong_id = format!(
            r#"{{"id":"{}","pubkey":"{}","kind":1,"content":"x","tags":[],"created_at":1700000000}}"#,
            "ab".repeat(32),
            keys.public_key().to_hex()
        );
        for bad in [request(&other), wrong_id, r#"{"kind":1}"#.to_owned()] {
            assert!(h.sign_event(&bad).await.is_err());
        }
        assert_eq!(count("sign"), 0.0);
    }

    #[wasm_bindgen_test]
    async fn absent_pubkey_is_sent_filled() {
        let (keys, h) = session();
        sign_shim(&format!(
            "globalThis.__req = e; return {};",
            signed_json(&keys)
        ));
        let event = r#"{"kind":1,"content":"hi","tags":[["t","x"]],"created_at":1700000000}"#;
        let _ = h.sign_event(event).await;
        let seen = js_sys::eval("globalThis.__req.pubkey").unwrap();
        assert_eq!(seen.as_string().unwrap(), keys.public_key().to_hex());
    }

    #[wasm_bindgen_test]
    async fn sig_only_is_refused() {
        use crate::signers::signer_traits::tests::unsigned;
        use nostr::event::{AsyncSignEvent, FinalizeEvent};
        let (keys, auth) = extension();
        let input = unsigned(keys.public_key());
        let sig = input.clone().finalize(&keys).unwrap().sig.to_string();
        sign_shim(&format!("return {{ sig: '{sig}' }};"));
        assert_signing_failed(auth.sign_event(&input.as_json()).await, INVALID);
        let traited = auth.sign_event_async(input).await.map(|e| e.as_json());
        assert_signing_failed(traited, INVALID);
    }

    #[wasm_bindgen_test]
    async fn nip44_refuses_changed_account() {
        let (_, h) = session();
        let other = nostr::key::Keys::generate().public_key().to_hex();
        shim(&format!(
            "globalThis.__n = {{ enc: 0, dec: 0 }}; globalThis.window = {{ nostr: {{ getPublicKey: async () => '{other}', nip44: {{ encrypt: async () => {{ globalThis.__n.enc += 1; return 'x'; }}, decrypt: async () => {{ globalThis.__n.dec += 1; return 'x'; }} }} }} }};"
        ));
        let enc = h.nip44_encrypt("pk", "x").await;
        assert!(matches!(enc, Err(NostrAuthError::SignerKeyMismatch)));
        let dec = h.nip44_decrypt("pk", "x").await;
        assert!(matches!(dec, Err(NostrAuthError::SignerKeyMismatch)));
        assert_eq!(count("enc"), 0.0);
        assert_eq!(count("dec"), 0.0);
    }

    fn extension() -> (nostr::key::Keys, crate::types::AuthResult) {
        let keys = nostr::key::Keys::generate();
        let auth = crate::types::AuthResult::Extension(Nip07Handle {
            public_key: keys.public_key(),
        });
        (keys, auth)
    }

    #[wasm_bindgen_test]
    async fn trait_signs_through_extension() {
        use crate::signers::signer_traits::tests::{assert_fields_equal, unsigned};
        use nostr::event::{AsyncSignEvent, FinalizeEvent};
        let (keys, auth) = extension();
        let input = unsigned(keys.public_key());
        let signed = input.clone().finalize(&keys).unwrap();
        js_sys::eval(&format!(
            "globalThis.window = {{ nostr: {{ signEvent: async () => ({}) }} }};",
            signed.as_json()
        ))
        .unwrap();
        let out = auth.sign_event_async(input.clone()).await.unwrap();
        assert_fields_equal(&input, &out);
        assert_eq!(out.id, signed.id);
    }

    #[wasm_bindgen_test]
    async fn null_and_undefined_results_are_typed() {
        use crate::signers::signer_traits::tests::unsigned;
        use nostr::event::AsyncSignEvent;
        let (keys, auth) = extension();
        for value in ["null", "undefined"] {
            js_sys::eval(&format!(
                "globalThis.window = {{ nostr: {{ signEvent: async () => {value} }} }};"
            ))
            .unwrap();
            let r = auth.sign_event_async(unsigned(keys.public_key())).await;
            assert!(matches!(
                r,
                Err(crate::types::NostrAuthError::SigningFailed(_))
            ));
        }
    }

    #[wasm_bindgen_test]
    async fn rejection_message_is_kept() {
        use crate::signers::signer_traits::tests::unsigned;
        use nostr::event::AsyncSignEvent;
        let (keys, auth) = extension();
        js_sys::eval(
            "globalThis.window = { nostr: { signEvent: async () => { throw new Error('denied by user'); } } };",
        )
        .unwrap();
        let err = auth
            .sign_event_async(unsigned(keys.public_key()))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, crate::types::NostrAuthError::SigningFailed(m) if m.contains("denied by user"))
        );
    }
}
