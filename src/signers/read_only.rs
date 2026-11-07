use nostr::key::PublicKey;
use nostr::nips::nip19::FromBech32;

use crate::types::NostrAuthError;

/// Read-only access — public key only, no signing capability.
#[derive(Clone)]
#[non_exhaustive]
pub struct ReadOnlyHandle {
    /// The authenticated user's public key.
    pub public_key: PublicKey,
}

/// Parses hex, `npub1...` or `nprofile1...`, and refuses a key off the curve. No error quotes the
/// input.
///
/// About half of all 64-character hex secret keys are also valid public keys, so a pasted hex secret
/// cannot always be detected: such a value is accepted, and the modal shows and persists it as a
/// public key.
impl core::str::FromStr for ReadOnlyHandle {
    type Err = NostrAuthError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let input = input.trim();
        let Some(public_key) = PublicKey::from_hex(input)
            .ok()
            .or_else(|| PublicKey::from_bech32(input).ok())
        else {
            return Err(NostrAuthError::InvalidPublicKey(
                "Expected npub1..., nprofile1..., or 64-char hex public key".into(),
            ));
        };
        if super::check_on_curve(&public_key).is_err() {
            return Err(NostrAuthError::InvalidPublicKey(
                "Not a valid public key. If this is a secret key, do not paste it here.".into(),
            ));
        }
        Ok(Self { public_key })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod tests {
    use super::*;

    #[test]
    fn readonly_parses_nprofile() {
        let nprofile = "nprofile1qqsrhuxx8l9ex335q7he0f09aej04zpazpl0ne2cgukyawd24mayt8gppemhxue69uhhytnc9e3k7mf0qyt8wumn8ghj7er2vfshxtnnv9jxkc3wvdhk6tclr7lsh";
        let h: ReadOnlyHandle = nprofile.parse().unwrap();
        assert_eq!(
            h.public_key.to_hex(),
            "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d"
        );
    }

    fn assert_rejected(input: &str) {
        let Err(error @ NostrAuthError::InvalidPublicKey(_)) = input.parse::<ReadOnlyHandle>()
        else {
            unreachable!("accepted or mistyped {input}");
        };
        let shown = format!("{error} {error:?}");
        for word in input.split_whitespace() {
            assert!(!shown.contains(word), "{shown}");
        }
    }

    #[test]
    fn readonly_rejects_off_curve() {
        use crate::signers::signer_traits::tests::off_curve;
        use nostr::key::{Keys, SecretKey};
        use nostr::nips::nip19::{Nip19Profile, ToBech32};
        let vectors = [
            off_curve(),
            PublicKey::from_hex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30")
                .unwrap(),
            PublicKey::from_hex("630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd")
                .unwrap(),
        ];
        for key in vectors {
            assert_rejected(&key.to_hex());
            assert_rejected(&key.to_bech32().unwrap());
            assert_rejected(&Nip19Profile::new(key, []).to_bech32().unwrap());
        }
        let nsec = Keys::new(SecretKey::from_hex(&"22".repeat(32)).unwrap());
        assert_rejected(&nsec.secret_key().to_bech32().unwrap());
        assert_rejected(&"a".repeat(63));
        assert_rejected("sentinelone sentineltwo sentinelthree sentinelfour");
    }

    #[test]
    fn readonly_accepts_on_curve_hex_secret() {
        let secret = "0000000000000000000000000000000000000000000000000000000000000001";
        let handle: ReadOnlyHandle = secret.parse().unwrap();
        assert_eq!(handle.public_key.to_hex(), secret);
    }
}
