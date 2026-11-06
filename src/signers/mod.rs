/// Browser-only helpers shared by the backends.
#[cfg(not(feature = "ssr"))]
mod browser;
/// NIP-07 browser extension backend.
mod nip07;
/// NIP-46 remote signer (bunker) backend.
mod nip46;
/// Passkey (WebAuthn PRF) backend.
mod passkey;
/// In-memory raw key backend (ncryptsec and raw nsec).
mod raw_key;
/// Read-only backend.
mod read_only;

pub use crate::types::AuthResult;
pub use nip07::Nip07Handle;
pub use nip46::BunkerSession;
pub use passkey::PasskeySession;
pub use raw_key::RawKeySession;
pub use read_only::ReadOnlyHandle;

#[cfg(test)]
#[cfg(feature = "ssr")]
mod server_tests {
    use super::*;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use nostr::key::Keys;

    use crate::types::NostrAuthError;

    pub(super) fn ready<F: Future>(fut: F) -> F::Output {
        match pin!(fut).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(out) => out,
            Poll::Pending => unreachable!("server stubs never suspend"),
        }
    }

    pub(super) fn text<T>(result: Result<T, NostrAuthError>) -> String {
        result.map_or_else(|e| e.to_string(), |_| "Ok".to_owned())
    }

    fn assert_send<T: Send>(_: T) {}

    #[test]
    fn server_futures_are_send() {
        let h = Nip07Handle {
            public_key: Keys::generate().public_key(),
        };
        let s = nip46::server_tests::bunker();
        assert_send(Nip07Handle::get_public_key());
        assert_send(h.sign_event("{}"));
        assert_send(h.nip44_encrypt("a", "b"));
        assert_send(h.nip44_decrypt("a", "b"));
        assert_send(BunkerSession::connect("bunker://x", 1));
        assert_send(s.sign_event("{}"));
        assert_send(s.nip44_encrypt("a", "b"));
        assert_send(s.nip44_decrypt("a", "b"));
        assert_send(PasskeySession::create("rp", "name"));
        assert_send(PasskeySession::authenticate(None));
        assert_send(AuthResult::Extension(h).sign_event("{}"));
    }
}
