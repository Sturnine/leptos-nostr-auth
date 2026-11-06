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
        Err(NostrAuthError::InvalidPublicKey(
            "Expected npub1..., nprofile1..., or 64-char hex public key".into(),
        ))
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
}
