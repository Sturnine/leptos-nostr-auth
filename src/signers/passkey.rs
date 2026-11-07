use nostr::key::{Keys, PublicKey};

use crate::types::NostrAuthError;

/// An active passkey session. The secret key is in-memory only; derived anew on each login.
///
/// On drop, nostr overwrites this session's copy with `non_secure_erase`: best effort, not
/// `zeroize`. The derivation's hash digest and hash state are not wiped, and NIP-44 calls leave
/// derived keys and plaintext unwiped.
///
/// A synced passkey gives the same key on devices using this crate with the same RP ID. Whether a
/// passkey syncs is up to its provider.
#[derive(Clone)]
pub struct PasskeySession {
    /// The authenticated user's public key.
    pub public_key: PublicKey,
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
    /// The ceremony starts at first poll, so spawning this from a click does not run it inside the
    /// click. `rp_id` goes to the browser as given.
    ///
    /// When the authenticator reports PRF as enabled with no output, this follows up with a `get`
    /// for the new credential. If that fails the credential still exists, and the error says to use
    /// it rather than create another.
    ///
    /// Dropping the future takes the browser's prompt down, where the browser honours it. To keep
    /// the prompt through a timeout or `select!`, keep polling the same future, or spawn it. A
    /// credential may already exist after a dropped `create`.
    ///
    /// # Errors
    ///
    /// Returns an error if the passkey creation fails.
    pub async fn create(rp_id: &str, rp_name: &str) -> Result<Self, NostrAuthError> {
        imp::begin_create(rp_id, rp_name)?.finish().await
    }

    /// Authenticate with an existing passkey under `rp_id`, which goes to the browser as given.
    ///
    /// The ceremony starts at first poll, so spawning this from a click does not run it inside the
    /// click.
    /// The same passkey + same PRF salt always produces the same Nostr key (deterministic).
    ///
    /// Pass `Some(credential_id)` to restrict the browser prompt to one specific
    /// stored credential (used when restoring a persisted session). Pass `None`
    /// for discoverable login, where the browser presents all stored passkeys
    /// for this origin and the user picks one (used for "I already have a
    /// passkey" with no prior session).
    ///
    /// Dropping the future takes the browser's prompt down, where the browser honours it. To keep
    /// the prompt through a timeout or `select!`, keep polling the same future, or spawn it.
    ///
    /// # Errors
    ///
    /// Returns an error when called with SSR features or when passkey authentication fails.
    pub async fn authenticate(
        rp_id: &str,
        credential_id: Option<Vec<u8>>,
    ) -> Result<Self, NostrAuthError> {
        imp::begin_authenticate(rp_id, credential_id.as_deref())?
            .finish()
            .await
    }

    /// Start a `get` now, so that it runs inside the caller's click handler.
    pub(crate) fn begin_authenticate(
        rp_id: &str,
        credential_id: Option<&[u8]>,
    ) -> Result<PendingPasskey, NostrAuthError> {
        imp::begin_authenticate(rp_id, credential_id)
    }

    /// Start a `create` now, so that it runs inside the caller's click handler.
    pub(crate) fn begin_create(
        rp_id: &str,
        rp_name: &str,
    ) -> Result<PendingPasskey, NostrAuthError> {
        imp::begin_create(rp_id, rp_name)
    }

    /// Sign a Nostr event using the in-memory derived key.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_event(&self, event_json: &str) -> Result<String, NostrAuthError> {
        super::sign_with_keys(&self.keys, event_json)
    }

    /// NIP-44 v2 encrypt with the in-memory key.
    ///
    /// # Errors
    ///
    /// [`NostrAuthError::InvalidPublicKey`] when `peer` is not on the curve, and
    /// [`NostrAuthError::EncryptionFailed`] when encryption fails.
    pub fn nip44_encrypt(
        &self,
        peer: &PublicKey,
        plaintext: &str,
    ) -> Result<String, NostrAuthError> {
        super::encrypt_with_keys(&self.keys, peer, plaintext)
    }

    /// NIP-44 decrypt with the in-memory key.
    ///
    /// # Errors
    ///
    /// [`NostrAuthError::InvalidPublicKey`] when `peer` is not on the curve, and
    /// [`NostrAuthError::EncryptionFailed`] when decryption fails.
    pub fn nip44_decrypt(
        &self,
        peer: &PublicKey,
        ciphertext: &str,
    ) -> Result<String, NostrAuthError> {
        super::decrypt_with_keys(&self.keys, peer, ciphertext)
    }

    #[cfg(test)]
    pub(crate) fn for_tests(keys: Keys, credential_id: Vec<u8>) -> Self {
        Self {
            public_key: keys.public_key(),
            keys,
            credential_id,
        }
    }
}

pub use imp::Pending as PendingPasskey;

#[cfg(not(feature = "ssr"))]
mod imp {
    use base64::Engine as _;
    use js_sys::{Array, Object, Reflect, Uint8Array};
    use nostr::key::{Keys, SecretKey};
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;
    use zeroize::Zeroizing;

    use super::PasskeySession;
    use crate::signers::browser::{js_err_msg, random_bytes, set, set_str};
    use crate::types::NostrAuthError;

    /// The raw UTF-8 bytes of `"nostr-key-v1"`, not hashed here: the WebAuthn client hashes them with
    /// its own context. Changing them changes every user's identity.
    pub(super) const PRF_SALT: &[u8] = b"nostr-key-v1";

    /// Takes the browser's prompt down when the ceremony's future is dropped.
    struct AbortOnDrop(web_sys::AbortController);

    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    /// Set a new controller's signal on the outer options object, not on `publicKey`.
    fn abort_guard(options: &Object) -> Result<AbortOnDrop, NostrAuthError> {
        let controller = web_sys::AbortController::new()
            .map_err(|e| NostrAuthError::PasskeyFailed(js_err_msg(&e)))?;
        set(options, "signal", &controller.signal());
        Ok(AbortOnDrop(controller))
    }

    /// A ceremony already started, whose result is not yet read.
    ///
    /// The promise is converted when the ceremony starts. An attempt aborted before its first poll
    /// would otherwise leave a rejection with no handler.
    pub struct Pending {
        credential: JsFuture,
        /// The RP ID for a `create`'s follow-up. `None` on a `get`.
        create_rp_id: Option<String>,
        /// Must outlive the await on `credential`. A partial move of that field keeps it alive.
        _abort: AbortOnDrop,
    }

    impl Pending {
        /// Await the ceremony and derive the session.
        pub async fn finish(self) -> Result<PasskeySession, NostrAuthError> {
            let credential = await_credential(self.credential).await?;
            let Some(rp_id) = self.create_rp_id else {
                return derive_from_credential(&credential);
            };
            match prf_outcome(&credential)? {
                PrfOutcome::Output(_) => derive_from_credential(&credential),
                PrfOutcome::EnabledWithoutOutput => {
                    let raw_id = credential_id_of(&credential)?;
                    follow_up_get(&rp_id, &raw_id)
                        .await
                        .map_err(follow_up_error)
                }
                PrfOutcome::Unavailable => Err(NostrAuthError::PasskeyNotSupported),
            }
        }
    }

    /// Read the key of a credential just created that gave no PRF output.
    async fn follow_up_get(rp_id: &str, raw_id: &[u8]) -> Result<PasskeySession, NostrAuthError> {
        let pending = begin_authenticate(rp_id, Some(raw_id))?;
        let credential = await_credential(pending.credential).await?;
        derive_from_credential(&credential)
    }

    /// The credential now exists, so a failed follow-up must not invite another `create`.
    fn follow_up_error(error: NostrAuthError) -> NostrAuthError {
        let inner = match error {
            NostrAuthError::PasskeyNotSupported => return error,
            NostrAuthError::PasskeyFailed(inner) => inner,
            other => other.to_string(),
        };
        NostrAuthError::PasskeyFailed(format!(
            "passkey created, but its key could not be read: {inner}. Use the existing passkey instead of creating another"
        ))
    }

    async fn await_credential(credential: JsFuture) -> Result<JsValue, NostrAuthError> {
        credential.await.map_err(|e| {
            web_sys::console::error_1(&e);
            NostrAuthError::PasskeyFailed(js_err_msg(&e))
        })
    }

    pub(super) fn begin_create(rp_id: &str, rp_name: &str) -> Result<Pending, NostrAuthError> {
        let window = web_sys::window()
            .ok_or_else(|| NostrAuthError::PasskeyFailed("no window object".into()))?;
        let credentials = window.navigator().credentials();

        // Build a random user ID (not linked to the Nostr key — just for WebAuthn bookkeeping)
        let user_id = random_bytes(16);
        let user_id_u8 = Uint8Array::from(user_id.as_slice());

        let options = Object::new();
        let pk_opts = Object::new();

        let rp = Object::new();
        set_str(&rp, "id", rp_id);
        set_str(&rp, "name", rp_name);
        set(&pk_opts, "rp", &rp);

        let user = Object::new();
        Reflect::set(&user, &"id".into(), &user_id_u8)
            .map_err(|e| NostrAuthError::PasskeyFailed(js_err_msg(&e)))?;
        set_str(&user, "name", "nostr");
        set_str(&user, "displayName", "Nostr Identity");
        set(&pk_opts, "user", &user);

        let challenge = Uint8Array::from(random_bytes(32).as_slice());
        set(&pk_opts, "challenge", &challenge);

        // pubKeyCredParams: ES256 (-7)
        let param = Object::new();
        set_str(&param, "type", "public-key");
        Reflect::set(&param, &"alg".into(), &(-7_i32).into())
            .map_err(|e| NostrAuthError::PasskeyFailed(js_err_msg(&e)))?;
        let params = Array::of1(&param);
        set(&pk_opts, "pubKeyCredParams", &params);

        let auth_sel = Object::new();
        set_str(&auth_sel, "residentKey", "required");
        set_str(&auth_sel, "userVerification", "required");
        set(&pk_opts, "authenticatorSelection", &auth_sel);

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
        let abort = abort_guard(&options)?;

        let promise = credentials
            .create_with_options(&options.unchecked_into())
            .map_err(|e| NostrAuthError::PasskeyFailed(format!("{e:?}")))?;

        Ok(Pending {
            credential: JsFuture::from(promise),
            create_rp_id: Some(rp_id.to_owned()),
            _abort: abort,
        })
    }

    pub(super) fn begin_authenticate(
        rp_id: &str,
        credential_id: Option<&[u8]>,
    ) -> Result<Pending, NostrAuthError> {
        let window = web_sys::window()
            .ok_or_else(|| NostrAuthError::PasskeyFailed("no window object".into()))?;
        let credentials = window.navigator().credentials();

        let options = Object::new();
        let pk_opts = Object::new();

        let challenge = Uint8Array::from(random_bytes(32).as_slice());
        set(&pk_opts, "challenge", &challenge);
        set_str(&pk_opts, "rpId", rp_id);
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
        let abort = abort_guard(&options)?;

        let promise = credentials
            .get_with_options(&options.unchecked_into())
            .map_err(|e| NostrAuthError::PasskeyFailed(format!("{e:?}")))?;

        Ok(Pending {
            credential: JsFuture::from(promise),
            create_rp_id: None,
            _abort: abort,
        })
    }

    #[cfg_attr(test, derive(Debug, PartialEq, Eq))]
    enum PrfOutcome {
        /// `prf.results` is present, with `first` as these bytes, wiped on drop.
        Output(Zeroizing<Vec<u8>>),
        /// `prf.enabled` is true and there are no results, as `create` is allowed to return.
        EnabledWithoutOutput,
        Unavailable,
    }

    fn prf_outcome(credential: &JsValue) -> Result<PrfOutcome, NostrAuthError> {
        let extensions = Reflect::get(credential, &"getClientExtensionResults".into())
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

        let Ok(prf) = Reflect::get(&extensions, &"prf".into()) else {
            return Ok(PrfOutcome::Unavailable);
        };
        let Ok(results) = Reflect::get(&prf, &"results".into()) else {
            return Ok(PrfOutcome::Unavailable);
        };

        if results.is_undefined() || results.is_null() {
            let enabled =
                Reflect::get(&prf, &"enabled".into()).is_ok_and(|v| v.as_bool() == Some(true));
            return Ok(if enabled {
                PrfOutcome::EnabledWithoutOutput
            } else {
                PrfOutcome::Unavailable
            });
        }

        let first = Reflect::get(&results, &"first".into()).map_err(|e| {
            NostrAuthError::PasskeyFailed(format!("no PRF first output: {}", js_err_msg(&e)))
        })?;

        Ok(PrfOutcome::Output(Zeroizing::new(
            Uint8Array::new(&first).to_vec(),
        )))
    }

    fn credential_id_of(credential: &JsValue) -> Result<Vec<u8>, NostrAuthError> {
        let raw_id = Reflect::get(credential, &"rawId".into())
            .map_err(|e| NostrAuthError::PasskeyFailed(format!("no rawId: {}", js_err_msg(&e))))?;
        Ok(Uint8Array::new(&raw_id).to_vec())
    }

    fn derive_from_credential(credential: &JsValue) -> Result<PasskeySession, NostrAuthError> {
        let credential_id = credential_id_of(credential)?;

        let PrfOutcome::Output(prf_bytes) = prf_outcome(credential)? else {
            return Err(NostrAuthError::PasskeyNotSupported);
        };

        let keys = keys_from_prf_output(&prf_bytes)?;
        let public_key = keys.public_key();

        Ok(PasskeySession {
            public_key,
            keys,
            credential_id,
        })
    }

    /// PRF output (32 bytes) → SHA-256 → secp256k1 private key. Changing this changes every user's
    /// identity.
    pub(super) fn keys_from_prf_output(prf_bytes: &[u8]) -> Result<Keys, NostrAuthError> {
        if prf_bytes.len() != 32 {
            return Err(NostrAuthError::PasskeyFailed(format!(
                "PRF output must be 32 bytes, got {}",
                prf_bytes.len()
            )));
        }

        let digest = sha256_bytes(prf_bytes);

        let secret_key = SecretKey::from_slice(&digest)
            .map_err(|e| NostrAuthError::PasskeyFailed(e.to_string()))?;

        Ok(Keys::new(secret_key))
    }

    /// Compute SHA-256 synchronously.
    pub(super) fn sha256_bytes(input: &[u8]) -> [u8; 32] {
        use bitcoin_hashes::sha256;
        sha256::Hash::hash(input).to_byte_array()
    }

    #[cfg(all(test, target_arch = "wasm32"))]
    #[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
    mod wasm_tests {
        use super::*;
        use wasm_bindgen_test::wasm_bindgen_test;

        fn credential(extensions: &str) -> JsValue {
            let source = format!(
                "({{ rawId: new Uint8Array([251, 255, 191]).buffer, getClientExtensionResults() {{ return {extensions}; }} }})"
            );
            js_sys::eval(&source).unwrap()
        }

        const OUTPUT_0_TO_31: &str =
            "{ prf: { results: { first: Uint8Array.from({ length: 32 }, (_, i) => i).buffer } } }";

        #[wasm_bindgen_test]
        fn derive_from_fake_credential() {
            let session = derive_from_credential(&credential(OUTPUT_0_TO_31)).unwrap();
            assert_eq!(
                session.public_key.to_hex(),
                "f8d6557dfcca8c44b8b9d16d33e3faa77e05286f992067a5453441f8b13d582e"
            );
            assert_eq!(session.credential_id, [0xfb, 0xff, 0xbf]);
        }

        #[wasm_bindgen_test]
        fn prf_output_buffer_is_wiped() {
            use crate::signers::memory_probe::matches;
            let fake = credential(
                "{ prf: { results: { first: Uint8Array.from({ length: 64 }, () => 1 + Math.floor(Math.random() * 255)).buffer } } }",
            );
            let PrfOutcome::Output(output) = prf_outcome(&fake).unwrap() else {
                unreachable!("the fake holds an output");
            };
            let expected = output.to_vec();
            let addr = output.as_ptr().addr();
            assert_eq!(matches(addr, &expected), expected.len());
            drop(output);
            assert!(matches(addr, &expected) <= 4);
        }

        #[wasm_bindgen_test]
        fn abort_guard_sets_outer_signal_and_aborts_on_drop() {
            let options = Object::new();
            let guard = abort_guard(&options).unwrap();
            let signal: web_sys::AbortSignal = Reflect::get(&options, &"signal".into())
                .unwrap()
                .unchecked_into();
            assert!(!signal.aborted());
            drop(guard);
            assert!(signal.aborted());
        }

        #[wasm_bindgen_test]
        fn prf_outcome_table() {
            let expected: Vec<u8> = (0..32).collect();
            for (extensions, want) in [
                (OUTPUT_0_TO_31, PrfOutcome::Output(Zeroizing::new(expected))),
                (
                    "{ prf: { results: {} } }",
                    PrfOutcome::Output(Zeroizing::new(Vec::new())),
                ),
                (
                    "{ prf: { enabled: true } }",
                    PrfOutcome::EnabledWithoutOutput,
                ),
                ("{ prf: { enabled: false } }", PrfOutcome::Unavailable),
                ("{ prf: {} }", PrfOutcome::Unavailable),
                ("{}", PrfOutcome::Unavailable),
            ] {
                assert_eq!(prf_outcome(&credential(extensions)).unwrap(), want);
            }
        }
    }
}

#[cfg(feature = "ssr")]
mod imp {
    use super::PasskeySession;
    use crate::signers::NOT_ON_SERVER;
    use crate::types::NostrAuthError;

    /// Server stub for the browser's in-flight ceremony.
    pub struct Pending;

    impl Pending {
        /// Server stub for `finish`.
        #[expect(
            clippy::unused_async,
            reason = "matches the browser signature, which awaits"
        )]
        pub async fn finish(self) -> Result<PasskeySession, NostrAuthError> {
            Err(NostrAuthError::PasskeyFailed(NOT_ON_SERVER.into()))
        }
    }

    pub(super) fn begin_create(_rp_id: &str, _rp_name: &str) -> Result<Pending, NostrAuthError> {
        Err(NostrAuthError::PasskeyFailed(NOT_ON_SERVER.into()))
    }

    pub(super) fn begin_authenticate(
        _rp_id: &str,
        _credential_id: Option<&[u8]>,
    ) -> Result<Pending, NostrAuthError> {
        Err(NostrAuthError::PasskeyFailed(NOT_ON_SERVER.into()))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod tests {
    use super::*;
    use crate::types::AuthResult;
    use nostr::event::Event;

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
    fn prf_salt_bytes() {
        assert_eq!(
            super::imp::PRF_SALT,
            [
                0x6e, 0x6f, 0x73, 0x74, 0x72, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x76, 0x31
            ]
        );
    }

    // Method for both vectors: output -> SHA-256 -> secp256k1 secret, computed outside the crate (Python hashlib and a pure-Python multiply, checked with openssl).
    #[cfg(not(feature = "ssr"))]
    #[test]
    fn prf_derivation_vector() {
        let input: Vec<u8> = (0..32).collect();
        let keys = super::imp::keys_from_prf_output(&input).unwrap();
        assert_eq!(
            keys.secret_key().to_secret_hex(),
            "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd"
        );
        assert_eq!(
            keys.public_key().to_hex(),
            "f8d6557dfcca8c44b8b9d16d33e3faa77e05286f992067a5453441f8b13d582e"
        );
    }

    #[cfg(not(feature = "ssr"))]
    #[test]
    fn nip44_uses_the_derived_key() {
        let input: Vec<u8> = (0..32).collect();
        let keys = super::imp::keys_from_prf_output(&input).unwrap();
        assert_eq!(
            keys.public_key().to_hex(),
            "f8d6557dfcca8c44b8b9d16d33e3faa77e05286f992067a5453441f8b13d582e"
        );
        let s = PasskeySession::for_tests(keys, vec![1]);
        let peer = Keys::generate();
        let ct = s.nip44_encrypt(&peer.public_key(), "hi").unwrap();
        let opened = nostr::nips::nip44::decrypt(peer.secret_key(), &s.public_key, &ct).unwrap();
        assert_eq!(opened, "hi");
    }

    #[cfg(not(feature = "ssr"))]
    #[test]
    fn prf_vector_sevens() {
        let keys = super::imp::keys_from_prf_output(&[7; 32]).unwrap();
        assert_eq!(
            keys.public_key().to_hex(),
            "5bf96bc947e9439cc6ab833bcd0e2dd8c155fdea32a6f787b70a5209206ed105"
        );
    }

    #[cfg(not(feature = "ssr"))]
    #[test]
    fn prf_output_wrong_length() {
        for len in [31, 33] {
            assert!(matches!(
                super::imp::keys_from_prf_output(&vec![7; len]),
                Err(NostrAuthError::PasskeyFailed(_))
            ));
        }
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
        assert_eq!(text(ready(PasskeySession::authenticate("rp", None))), want);
    }
}
