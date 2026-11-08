use nostr::key::{Keys, PublicKey};
use nostr::nips::nip19::FromBech32;

use crate::types::NostrAuthError;

/// In-memory raw key session. Used for NIP-49 ncryptsec and (feature-gated) raw nsec paste.
///
/// The key stays in wasm memory for this struct's life, and each clone holds its own copy. On drop,
/// nostr overwrites that copy with `non_secure_erase`: best effort, not `zeroize`, and it cannot
/// reach bytes the compiler moved or copied. NIP-44 calls leave derived keys and plaintext unwiped.
/// Logout ends use of the key; it does not prove the memory is clean.
#[derive(Clone)]
pub struct RawKeySession {
    /// The authenticated user's public key.
    pub public_key: PublicKey,
    keys: Keys,
}

impl RawKeySession {
    /// Decrypt a NIP-49 `ncryptsec1...` string with a password.
    ///
    /// scrypt runs synchronously and blocks the calling thread. `spawn_local` does not move it off
    /// the main thread, so callers wanting a spinner must let the browser paint first.
    ///
    /// The decrypt also grows the page's wasm memory by 64 MiB at `log_n = 16` and 256 MiB at 18,
    /// and wasm memory never shrinks. On a low-memory phone the allocation at 17 or 18 can fail,
    /// which aborts the whole app.
    ///
    /// # Errors
    ///
    /// Returns an error when decrypting fails.
    pub fn from_ncryptsec(ncryptsec: &str, password: &str) -> Result<Self, NostrAuthError> {
        let encrypted = nostr::nips::nip49::EncryptedSecretKey::from_bech32(ncryptsec)
            .map_err(|e| NostrAuthError::InvalidNcryptsec(e.to_string()))?;

        let secret_key = encrypted.decrypt(password).map_err(|e| {
            if e.kind() == nostr::error::ErrorKind::Crypto {
                NostrAuthError::WrongPassword
            } else {
                NostrAuthError::InvalidNcryptsec(e.to_string())
            }
        })?;

        let keys = Keys::new(secret_key);
        Ok(Self {
            public_key: keys.public_key(),
            keys,
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
        use nostr::key::SecretKey;

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
        let keys = Keys::new(secret_key);
        Ok(Self {
            public_key: keys.public_key(),
            keys,
        })
    }

    /// Sign a Nostr event with the in-memory key.
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
    pub(crate) fn for_tests(keys: Keys) -> Self {
        Self {
            public_key: keys.public_key(),
            keys,
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod tests {
    use super::*;
    use crate::types::AuthResult;
    use nostr::event::Event;
    use nostr::nips::nip19::ToBech32;
    use nostr::nips::nip49::EncryptedSecretKey;

    const CRYPTSEC: &str = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
    const CRYPTSEC_PUBKEY: &str =
        "672a31bfc59d3f04548ec9b7daeeba2f61814e8ccc40448045007f5479f693a3";

    // The NIP-49 spec test vector.

    #[test]
    fn ncryptsec_correct_password() {
        let s = RawKeySession::from_ncryptsec(CRYPTSEC, "nostr").unwrap();
        assert_eq!(s.public_key.to_hex(), CRYPTSEC_PUBKEY);
    }

    #[test]
    fn ncryptsec_wrong_password() {
        let r = RawKeySession::from_ncryptsec(CRYPTSEC, "wrong");
        assert!(matches!(r, Err(NostrAuthError::WrongPassword)));
    }

    #[test]
    fn ncryptsec_over_cost_cap() {
        let mut bytes = EncryptedSecretKey::from_bech32(CRYPTSEC).unwrap().as_vec();
        *bytes.get_mut(1).unwrap() = EncryptedSecretKey::MAX_LOG_N + 1;
        let over = EncryptedSecretKey::from_slice(&bytes)
            .unwrap()
            .to_bech32()
            .unwrap();
        let r = RawKeySession::from_ncryptsec(&over, "nostr");
        assert!(matches!(r, Err(NostrAuthError::InvalidNcryptsec(_))));
    }

    #[test]
    fn ncryptsec_malformed() {
        let r = RawKeySession::from_ncryptsec("not-an-ncryptsec", "nostr");
        assert!(matches!(r, Err(NostrAuthError::InvalidNcryptsec(_))));
    }

    #[test]
    fn ncryptsec_errors_quote_no_input() {
        use nostr::key::SecretKey;
        let hex = "22".repeat(32);
        let nsec = SecretKey::from_hex(&hex).unwrap().to_bech32().unwrap();
        let mut bytes = EncryptedSecretKey::from_bech32(CRYPTSEC).unwrap().as_vec();
        *bytes.get_mut(1).unwrap() = EncryptedSecretKey::MAX_LOG_N + 1;
        let over = EncryptedSecretKey::from_slice(&bytes)
            .unwrap()
            .to_bech32()
            .unwrap();
        for input in [nsec.as_str(), hex.as_str(), over.as_str()] {
            let Err(error) = RawKeySession::from_ncryptsec(input, "SENTINELPASSWORD") else {
                unreachable!("{input} opened");
            };
            assert!(matches!(error, NostrAuthError::InvalidNcryptsec(_)));
            let shown = format!("{error} {error:?}");
            for quoted in [
                nsec.as_str(),
                hex.as_str(),
                over.as_str(),
                "SENTINELPASSWORD",
            ] {
                assert!(!shown.contains(quoted), "{shown}");
            }
        }
    }

    #[test]
    fn raw_key_signing_verifies() {
        let s = RawKeySession::from_ncryptsec(CRYPTSEC, "nostr").unwrap();
        let unsigned = format!(
            r#"{{"pubkey":"{CRYPTSEC_PUBKEY}","created_at":1700000000,"kind":1,"tags":[],"content":"hi"}}"#
        );
        let signed = s.sign_event(&unsigned).unwrap();
        Event::from_json(signed).unwrap().verify().unwrap();
    }

    #[test]
    fn raw_key_rejects_malformed_json_and_names_method() {
        let keys = Keys::generate();
        let s = RawKeySession {
            public_key: keys.public_key(),
            keys,
        };
        assert!(matches!(
            s.sign_event("{"),
            Err(NostrAuthError::Serialization(_))
        ));
        assert_eq!(AuthResult::Ncryptsec(s).method_name(), "Encrypted Key");
    }

    #[cfg(feature = "insecure_nsec_input")]
    #[test]
    fn nsec_import_signs_and_verifies() {
        let hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let s = RawKeySession::from_nsec_or_hex(hex).unwrap();
        let unsigned = format!(
            r#"{{"pubkey":"{}","created_at":1700000000,"kind":1,"tags":[],"content":"hi"}}"#,
            s.public_key.to_hex()
        );
        let signed = s.sign_event(&unsigned).unwrap();
        Event::from_json(signed).unwrap().verify().unwrap();
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod wasm_tests {
    use super::*;
    use crate::signers::memory_probe::byte_at;
    use wasm_bindgen_test::wasm_bindgen_test;

    fn holds_run(start: usize, len: usize, run: &[u8; 32]) -> bool {
        let end = start.saturating_add(len).saturating_sub(run.len());
        (start..=end).any(|at| {
            run.iter()
                .zip(at..)
                .all(|(byte, address)| byte_at(address) == *byte)
        })
    }

    // Pins upstream's erase within one boxed value. Says nothing about NIP-44 or other copies.
    #[wasm_bindgen_test]
    fn keys_drop_overwrites_secret() {
        let keys = Box::new(Keys::generate());
        let run = keys.secret_key().secret_bytes();
        let start = core::ptr::from_ref::<Keys>(&keys).addr();
        let len = core::mem::size_of::<Keys>();
        assert!(holds_run(start, len, &run));
        drop(keys);
        assert!(!holds_run(start, len, &run));
    }

    #[wasm_bindgen_test]
    fn holds_run_finds_a_planted_run() {
        let run = Keys::generate().secret_key().secret_bytes();
        let boxed = Box::new(run);
        let start = core::ptr::from_ref::<[u8; 32]>(&boxed).addr();
        assert!(holds_run(start.checked_sub(4).unwrap(), 72, &run));
    }

    #[wasm_bindgen_test]
    fn holds_run_checks_the_last_offset() {
        let run = Keys::generate().secret_key().secret_bytes();
        let boxed = Box::new(run);
        let start = core::ptr::from_ref::<[u8; 32]>(&boxed).addr();
        assert!(holds_run(start, 32, &run));
    }
}
