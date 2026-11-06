use nostr::key::{Keys, PublicKey};

use crate::types::NostrAuthError;

/// An active passkey session. The secret key is in-memory only; derived anew on each login.
///
/// The passkey (and by extension, your Nostr identity) syncs via iCloud Keychain on Apple
/// devices, or Google Password Manager / Windows Hello on other platforms.
#[derive(Clone)]
pub struct PasskeySession {
    /// The authenticated user's public key.
    pub public_key: PublicKey,
    /// In-memory-only keypair derived from the WebAuthn PRF output.
    keys: Keys,
    /// Raw credential ID bytes, as returned by the browser's WebAuthn API
    /// (`credential.rawId`). Not encoded — callers that persist this (see
    /// `PersistedSession::passkey_credential_id`) base64url-encode it themselves;
    /// `authenticate` takes raw bytes back, not an encoded string.
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
        imp::create(rp_id, rp_name).await
    }

    /// Authenticate with an existing passkey.
    ///
    /// On macOS/iOS: triggers Touch ID / Face ID sheet.
    /// The same passkey + same PRF salt always produces the same Nostr key (deterministic).
    ///
    /// Pass `Some(credential_id)` to restrict the browser prompt to one specific
    /// stored credential (used when restoring a persisted session). Pass `None`
    /// for discoverable login, where the browser presents all stored passkeys
    /// for this origin and the user picks one (used for "I already have a
    /// passkey" with no prior session).
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when passkey authentication fails.
    pub async fn authenticate(credential_id: Option<Vec<u8>>) -> Result<Self, NostrAuthError> {
        imp::authenticate(credential_id.as_deref()).await
    }

    /// Sign a Nostr event using the in-memory derived key.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        super::sign_with_keys(&self.keys, event_json)
    }
}

/// Browser implementation.
#[cfg(not(feature = "ssr"))]
mod imp {
    use base64::Engine as _;
    use js_sys::{Array, Object, Reflect, Uint8Array};
    use nostr::key::{Keys, SecretKey};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;

    use super::PasskeySession;
    use crate::signers::browser::{js_err_msg, random_bytes, set, set_str};
    use crate::types::NostrAuthError;

    /// Fixed PRF salt (same as Roadflare iOS: `SHA256("nostr-key-v1")` raw bytes passed as salt).
    /// This constant is the UTF-8 bytes of "nostr-key-v1" — WebAuthn PRF hashes them internally.
    const PRF_SALT: &[u8] = b"nostr-key-v1";

    /// Run the WebAuthn creation ceremony and derive the key.
    pub(super) async fn create(
        rp_id: &str,
        rp_name: &str,
    ) -> Result<PasskeySession, NostrAuthError> {
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
        Reflect::set(&user, &"id".into(), &user_id_u8)
            .map_err(|e| NostrAuthError::PasskeyFailed(js_err_msg(&e)))?;
        set_str(&user, "name", "nostr");
        set_str(&user, "displayName", "Nostr Identity");
        set(&pk_opts, "user", &user);

        // challenge
        let challenge = Uint8Array::from(random_bytes(32).as_slice());
        set(&pk_opts, "challenge", &challenge);

        // pubKeyCredParams: ES256 (-7)
        let param = Object::new();
        set_str(&param, "type", "public-key");
        Reflect::set(&param, &"alg".into(), &(-7_i32).into())
            .map_err(|e| NostrAuthError::PasskeyFailed(js_err_msg(&e)))?;
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
        Reflect::set(&prf_eval, &"first".into(), &salt_u8)
            .map_err(|e| NostrAuthError::PasskeyFailed(js_err_msg(&e)))?;
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

        derive_from_credential(&credential)
    }

    /// Run the WebAuthn assertion ceremony and derive the key.
    pub(super) async fn authenticate(
        credential_id: Option<&[u8]>,
    ) -> Result<PasskeySession, NostrAuthError> {
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
        Reflect::set(&prf_eval, &"first".into(), &salt_u8)
            .map_err(|e| NostrAuthError::PasskeyFailed(js_err_msg(&e)))?;
        set(&prf, "eval", &prf_eval);

        if let Some(credential_id) = credential_id {
            // Restrict assertion to the stored credential
            let cred_descriptor = Object::new();
            set_str(&cred_descriptor, "type", "public-key");
            let cred_id_u8 = Uint8Array::from(credential_id);
            set(&cred_descriptor, "id", &cred_id_u8);
            let allow_creds = Array::of1(&cred_descriptor);
            set(&pk_opts, "allowCredentials", &allow_creds);

            // evalByCredential for spec-compliant browsers that prefer it over eval
            let cred_id_b64 =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(credential_id);
            let eval_by_cred = Object::new();
            let prf_eval_ebc = Object::new();
            let salt_u8_ebc = Uint8Array::from(PRF_SALT);
            Reflect::set(&prf_eval_ebc, &"first".into(), &salt_u8_ebc)
                .map_err(|e| NostrAuthError::PasskeyFailed(js_err_msg(&e)))?;
            Reflect::set(&eval_by_cred, &cred_id_b64.into(), &prf_eval_ebc)
                .map_err(|e| NostrAuthError::PasskeyFailed(js_err_msg(&e)))?;
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

        derive_from_credential(&credential)
    }

    /// Derive the Nostr keypair from a WebAuthn credential's PRF output.
    ///
    /// Flow (mirrors Roadflare iOS):
    ///   PRF output (32 bytes) → SHA-256 → secp256k1 private key
    fn derive_from_credential(credential: &JsValue) -> Result<PasskeySession, NostrAuthError> {
        // Extract credential ID
        let raw_id = Reflect::get(credential, &"rawId".into())
            .map_err(|e| NostrAuthError::PasskeyFailed(format!("no rawId: {}", js_err_msg(&e))))?;
        let cred_id_u8 = Uint8Array::new(&raw_id);
        let credential_id = cred_id_u8.to_vec();

        // Navigate: credential.getClientExtensionResults().prf.results.first
        let get_exts = Reflect::get(credential, &"getClientExtensionResults".into())
            .and_then(|f| {
                f.dyn_ref::<js_sys::Function>()
                    .ok_or(JsValue::UNDEFINED)?
                    .call0(credential)
            })
            .map_err(|e| {
                NostrAuthError::PasskeyFailed(format!(
                    "getClientExtensionResults failed: {}",
                    js_err_msg(&e)
                ))
            })?;

        #[expect(
            clippy::map_err_ignore,
            reason = "any failure here means no PRF support, which the returned error already conveys"
        )]
        let prf_results = Reflect::get(&get_exts, &"prf".into())
            .and_then(|p| Reflect::get(&p, &"results".into()))
            .map_err(|_| NostrAuthError::PasskeyNotSupported)?;

        if prf_results.is_undefined() || prf_results.is_null() {
            return Err(NostrAuthError::PasskeyNotSupported);
        }

        let first = Reflect::get(&prf_results, &"first".into()).map_err(|e| {
            NostrAuthError::PasskeyFailed(format!("no PRF first output: {}", js_err_msg(&e)))
        })?;

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

        let keys = Keys::new(secret_key);
        let public_key = keys.public_key();

        Ok(PasskeySession {
            public_key,
            keys,
            credential_id,
        })
    }

    /// Compute SHA-256 synchronously.
    pub(super) fn sha256_bytes(input: &[u8]) -> [u8; 32] {
        use bitcoin_hashes::sha256;
        sha256::Hash::hash(input).to_byte_array()
    }
}

/// Server stubs.
#[cfg(feature = "ssr")]
mod imp {
    use super::PasskeySession;
    use crate::signers::NOT_ON_SERVER;
    use crate::types::NostrAuthError;

    /// Server stub for `create`.
    pub(super) async fn create(
        _rp_id: &str,
        _rp_name: &str,
    ) -> Result<PasskeySession, NostrAuthError> {
        Err(NostrAuthError::PasskeyFailed(NOT_ON_SERVER.into()))
    }

    /// Server stub for `authenticate`.
    pub(super) async fn authenticate(
        _credential_id: Option<&[u8]>,
    ) -> Result<PasskeySession, NostrAuthError> {
        Err(NostrAuthError::PasskeyFailed(NOT_ON_SERVER.into()))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod tests {
    use super::*;
    use crate::types::AuthResult;
    use nostr::event::Event;

    // Expected values were computed outside the crate (shasum, Python hashlib and a pure-Python secp256k1 multiply).

    #[test]
    fn passkey_signs_rejects_malformed_json_and_names_method() {
        let keys = Keys::generate();
        let s = PasskeySession {
            public_key: keys.public_key(),
            keys,
            credential_id: vec![1, 2, 3],
        };
        assert!(matches!(
            s.sign_event("{"),
            Err(NostrAuthError::Serialization(_))
        ));
        let unsigned = format!(
            r#"{{"pubkey":"{}","created_at":1700000000,"kind":1,"tags":[],"content":"hi"}}"#,
            s.public_key.to_hex()
        );
        let signed = s.sign_event(&unsigned).unwrap();
        Event::from_json(signed).unwrap().verify().unwrap();
        assert_eq!(AuthResult::Passkey(s).method_name(), "Passkey");
    }

    #[cfg(not(feature = "ssr"))]
    #[test]
    fn sha256_abc_vector() {
        let d = super::imp::sha256_bytes(b"abc");
        let hex = bitcoin_hashes::sha256::Hash::from_byte_array(d).to_string();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[cfg(not(feature = "ssr"))]
    #[test]
    fn prf_derivation_vector() {
        let input: Vec<u8> = (0..32).collect();
        let digest = super::imp::sha256_bytes(&input);
        let hex = bitcoin_hashes::sha256::Hash::from_byte_array(digest).to_string();
        assert_eq!(
            hex,
            "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
        );
        let sk = nostr::key::SecretKey::from_slice(&digest).unwrap();
        assert_eq!(
            Keys::new(sk).public_key().to_hex(),
            "f8d6557dfcca8c44b8b9d16d33e3faa77e05286f992067a5453441f8b13d582e"
        );
    }
}

#[cfg(test)]
#[cfg(feature = "ssr")]
mod server_tests {
    use super::super::server_tests::{ready, text};
    use super::*;

    #[test]
    fn passkey_server_stubs() {
        let want = "Passkey operation failed: not available on server";
        assert_eq!(text(ready(PasskeySession::create("rp", "name"))), want);
        assert_eq!(text(ready(PasskeySession::authenticate(None))), want);
    }
}
