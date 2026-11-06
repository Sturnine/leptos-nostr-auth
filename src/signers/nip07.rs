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
    /// Returns an error when called with SSR features or when getting the public key fails.
    pub async fn get_public_key() -> Result<Self, NostrAuthError> {
        imp::get_public_key().await
    }

    /// Sign a Nostr event via the extension.
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when signing fails.
    pub async fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        imp::sign_event(event_json).await
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
        imp::nip44_encrypt(recipient_hex, plaintext).await
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
        imp::nip44_decrypt(sender_hex, ciphertext).await
    }
}

/// Browser implementation.
#[cfg(not(feature = "ssr"))]
mod imp {
    use nostr::key::PublicKey;
    use wasm_bindgen::prelude::*;

    use super::Nip07Handle;
    use crate::signers::browser::js_err_msg;
    use crate::types::NostrAuthError;

    // JS bindings for window.nostr (NIP-07) — WASM-only
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

    /// Request the public key from the extension.
    pub(super) async fn get_public_key() -> Result<Nip07Handle, NostrAuthError> {
        let js_pk = nostr_get_public_key()
            .await
            .map_err(|e| NostrAuthError::ExtensionRejected(js_err_msg(&e)))?;
        let hex = js_pk
            .as_string()
            .ok_or_else(|| NostrAuthError::ExtensionRejected("expected string pubkey".into()))?;
        let pk = PublicKey::from_hex(&hex)
            .map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))?;
        Ok(Nip07Handle { public_key: pk })
    }

    /// Sign an event through the extension.
    pub(super) async fn sign_event(event_json: &str) -> Result<String, NostrAuthError> {
        let event_val = js_sys::JSON::parse(event_json).map_err(|e| {
            NostrAuthError::SigningFailed(format!("invalid event JSON: {}", js_err_msg(&e)))
        })?;
        let signed = nostr_sign_event(event_val)
            .await
            .map_err(|e| NostrAuthError::SigningFailed(js_err_msg(&e)))?;
        js_sys::JSON::stringify(&signed)
            .map(|s| s.as_string().unwrap_or_default())
            .map_err(|e| {
                NostrAuthError::SigningFailed(format!(
                    "could not stringify signed event: {}",
                    js_err_msg(&e)
                ))
            })
    }

    /// NIP-44 encrypt through the extension.
    pub(super) async fn nip44_encrypt(
        recipient_hex: &str,
        plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        nostr_nip44_encrypt(recipient_hex, plaintext)
            .await
            .map_err(|e| NostrAuthError::SigningFailed(js_err_msg(&e)))?
            .as_string()
            .ok_or_else(|| NostrAuthError::SigningFailed("expected string ciphertext".into()))
    }

    /// NIP-44 decrypt through the extension.
    pub(super) async fn nip44_decrypt(
        sender_hex: &str,
        ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        nostr_nip44_decrypt(sender_hex, ciphertext)
            .await
            .map_err(|e| NostrAuthError::SigningFailed(js_err_msg(&e)))?
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
    pub(super) async fn sign_event(_event_json: &str) -> Result<String, NostrAuthError> {
        Err(NostrAuthError::SigningFailed(NOT_ON_SERVER.into()))
    }

    /// Server stub for `nip44_encrypt`.
    pub(super) async fn nip44_encrypt(
        _recipient_hex: &str,
        _plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        Err(NostrAuthError::SigningFailed(NOT_ON_SERVER.into()))
    }

    /// Server stub for `nip44_decrypt`.
    pub(super) async fn nip44_decrypt(
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

    const SHIM: &str = r#"globalThis.window = { nostr: {
        getPublicKey: async () => "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d",
        signEvent: async (e) => Object.assign({}, e, { id: "00", sig: "11" }),
        nip44: {
            encrypt: async (pk, pt) => "enc:" + pk + ":" + pt,
            decrypt: async (pk, ct) => "dec:" + pk + ":" + ct,
        },
    } };"#;

    #[wasm_bindgen_test]
    async fn nip07_calls_reach_window_nostr() {
        js_sys::eval(SHIM).unwrap();
        let h = Nip07Handle::get_public_key().await.unwrap();
        assert_eq!(
            h.public_key.to_hex(),
            "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
        );
        let signed = h.sign_event(r#"{"kind":1}"#).await.unwrap();
        let v: serde_json::Value = serde_json::from_str(&signed).unwrap();
        assert_eq!(v.get("sig").and_then(|s| s.as_str()), Some("11"));
        assert_eq!(h.nip44_encrypt("pk", "hi").await.unwrap(), "enc:pk:hi");
        assert_eq!(h.nip44_decrypt("pk", "ct").await.unwrap(), "dec:pk:ct");
    }
}
