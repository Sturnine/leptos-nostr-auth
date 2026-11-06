use core::future::Future;
use core::pin::Pin;

use nostr::event::{AsyncSignEvent, Event, UnsignedEvent};
use nostr::key::{AsyncGetPublicKey, PublicKey};

use crate::types::{AuthResult, NostrAuthError};

/// `SendWrapper` panics on another thread, so it is created at first poll, leaving the future free
/// to move until then. Server futures are `Send` and move between worker threads, so they get none.
#[cfg(not(feature = "ssr"))]
fn send_future<'a, T: 'a, F: Future<Output = T> + 'a>(
    make: impl FnOnce() -> F + Send + 'a,
) -> Pin<Box<dyn Future<Output = T> + Send + 'a>> {
    Box::pin(async move { send_wrapper::SendWrapper::new(make()).await })
}

/// Server futures need no wrapper.
#[cfg(feature = "ssr")]
fn send_future<'a, T: 'a, F: Future<Output = T> + Send + 'a>(
    make: impl FnOnce() -> F,
) -> Pin<Box<dyn Future<Output = T> + Send + 'a>> {
    Box::pin(make())
}

/// Returns the session's public key, the same value as [`AuthResult::public_key`]. It asks no signer
/// and never fails, including on a read-only session or a closed bunker session.
impl AsyncGetPublicKey for AuthResult {
    type Error = NostrAuthError;

    fn get_public_key_async(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<PublicKey, Self::Error>> + Send + '_>> {
        Box::pin(core::future::ready(Ok(self.public_key())))
    }
}

/// Signs through [`AuthResult::sign_event`]. A read-only session returns
/// [`NostrAuthError::SigningFailed`], and a closed bunker session returns
/// [`NostrAuthError::BunkerSessionClosed`].
///
/// The future is `Send`, as the trait requires, and can move between threads until its first poll.
/// Without the `ssr` feature, a future that has suspended must stay on its thread, or it panics.
/// Key, read-only and closed sessions finish in their first poll, and browser wasm has one thread.
///
/// On `wasm32-unknown-unknown`, `UnsignedEvent::finalize_async` needs no time provider.
/// `EventBuilder::finalize_async`, and any `nostr` helper that builds through `EventBuilder` such as
/// NIP-98 authorization, reaches `Timestamp::now`, which needs
/// `universal_time::define_time_provider!` in your binary. See the README.
///
/// `finalize_async` returns `nostr::error::Error`. The original error is its source. With
/// `core::error::Error` in scope:
/// `err.source().and_then(|s| s.downcast_ref::<NostrAuthError>())`.
impl AsyncSignEvent for AuthResult {
    type Error = NostrAuthError;

    fn sign_event_async(
        &self,
        unsigned: UnsignedEvent,
    ) -> Pin<Box<dyn Future<Output = Result<Event, Self::Error>> + Send + '_>> {
        send_future(move || async move {
            let signed = self.sign_event(&unsigned.as_json()).await?;
            Event::from_json(signed).map_err(|e| {
                NostrAuthError::SigningFailed(format!("signer returned an invalid event: {e}"))
            })
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
pub(in crate::signers) mod tests {
    use super::*;
    use crate::signers::{Nip07Handle, PasskeySession, RawKeySession, ReadOnlyHandle};
    use core::error::Error as _;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use nostr::error::ErrorKind;
    use nostr::event::{FinalizeEventAsync, Kind, Tag};
    use nostr::key::Keys;
    use nostr::types::Timestamp;
    use std::sync::Arc;

    pub(in crate::signers) fn ready<F: Future>(fut: F) -> F::Output {
        match pin!(fut).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(out) => out,
            Poll::Pending => unreachable!("this future finishes in its first poll"),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub(in crate::signers) struct PendingOnce(bool);

    #[cfg(not(target_arch = "wasm32"))]
    impl PendingOnce {
        pub(in crate::signers) const fn new() -> Self {
            Self(false)
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    impl Future for PendingOnce {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                Poll::Pending
            }
        }
    }

    pub(in crate::signers) fn unsigned(pubkey: PublicKey) -> UnsignedEvent {
        UnsignedEvent::new(
            pubkey,
            Timestamp::from_secs(1_700_000_000),
            Kind::TextNote,
            [Tag::hashtag("x")],
            "hi",
        )
    }

    pub(in crate::signers) fn assert_fields_equal(input: &UnsignedEvent, out: &Event) {
        out.verify().unwrap();
        assert_eq!(out.pubkey, input.pubkey);
        assert_eq!(out.created_at, input.created_at);
        assert_eq!(out.kind, input.kind);
        assert_eq!(out.tags, input.tags);
        assert_eq!(out.content, input.content);
    }

    fn keyed() -> (Keys, AuthResult, AuthResult) {
        let keys = Keys::generate();
        let nc = AuthResult::Ncryptsec(RawKeySession::for_tests(keys.clone()));
        let pk = AuthResult::Passkey(PasskeySession::for_tests(keys.clone(), vec![1]));
        (keys, nc, pk)
    }

    fn read_only() -> AuthResult {
        AuthResult::ReadOnly(ReadOnlyHandle {
            public_key: Keys::generate().public_key(),
        })
    }

    fn assert_signer<
        S: AsyncGetPublicKey<Error = NostrAuthError>
            + AsyncSignEvent<Error = NostrAuthError>
            + Send
            + Sync,
    >(
        _: &S,
    ) {
    }

    fn assert_send<T: Send>(_: T) {}

    #[test]
    fn auth_result_is_send_sync_nostr_signer() {
        let (keys, nc, _) = keyed();
        assert_signer(&nc);
        assert_send(nc.get_public_key_async());
        assert_send(nc.sign_event_async(unsigned(keys.public_key())));
        let _: Arc<dyn AsyncSignEvent<Error = NostrAuthError>> = Arc::new(nc);
    }

    #[test]
    fn get_public_key_async_returns_session_key() {
        let (keys, nc, pk) = keyed();
        let ext_key = Keys::generate().public_key();
        let ext = AuthResult::Extension(Nip07Handle {
            public_key: ext_key,
        });
        let ro = read_only();
        assert_eq!(ready(ext.get_public_key_async()).unwrap(), ext_key);
        assert_eq!(ready(ro.get_public_key_async()).unwrap(), ro.public_key());
        assert_eq!(ready(nc.get_public_key_async()).unwrap(), keys.public_key());
        assert_eq!(ready(pk.get_public_key_async()).unwrap(), keys.public_key());
    }

    #[test]
    fn sign_event_async_signs_with_local_keys() {
        let (keys, nc, pk) = keyed();
        let input = unsigned(keys.public_key());
        for auth in [nc, pk] {
            let out = ready(auth.sign_event_async(input.clone())).unwrap();
            assert_fields_equal(&input, &out);
        }
    }

    #[test]
    fn read_only_signing_is_typed() {
        let auth = read_only();
        let input = unsigned(auth.public_key());
        let direct = ready(auth.sign_event_async(input.clone())).unwrap_err();
        assert_eq!(
            direct.to_string(),
            "Signing failed: Read-only session cannot sign events"
        );
        let wrapped = ready(input.finalize_async(&auth)).unwrap_err();
        assert_eq!(wrapped.kind(), ErrorKind::Other);
        assert!(wrapped.to_string().contains("Read-only session cannot sign events"));
        let source = wrapped
            .source()
            .and_then(|s| s.downcast_ref::<NostrAuthError>());
        assert!(matches!(source, Some(NostrAuthError::SigningFailed(_))));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn event_builder_finalize_async_signs_raw_key() {
        use nostr::event::EventBuilder;
        let (keys, nc, _) = keyed();
        let ts = Timestamp::from_secs(1_700_000_000);
        let custom = ready(
            EventBuilder::new(Kind::TextNote, "hi")
                .custom_created_at(ts)
                .finalize_async(&nc),
        )
        .unwrap();
        custom.verify().unwrap();
        assert_eq!(custom.pubkey, keys.public_key());
        assert_eq!(custom.created_at, ts);
        let now = ready(EventBuilder::new(Kind::TextNote, "hi").finalize_async(&nc)).unwrap();
        now.verify().unwrap();
        assert_eq!(now.pubkey, keys.public_key());
        assert!(now.created_at.as_secs() > 1_577_836_800);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn event_builder_read_only_is_typed() {
        use nostr::event::EventBuilder;
        let auth = read_only();
        let err = ready(EventBuilder::new(Kind::TextNote, "hi").finalize_async(&auth)).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Other);
        let source = err.source().and_then(|s| s.downcast_ref::<NostrAuthError>());
        assert!(matches!(source, Some(NostrAuthError::SigningFailed(_))));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn future_created_here_signs_on_another_thread() {
        let (keys, nc, _) = keyed();
        let input = unsigned(keys.public_key());
        let fut = nc.sign_event_async(input.clone());
        let out = std::thread::scope(|s| s.spawn(move || ready(fut)).join().unwrap()).unwrap();
        assert_fields_equal(&input, &out);
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn extension_reports_server_stub_through_trait() {
        let auth = AuthResult::Extension(Nip07Handle {
            public_key: Keys::generate().public_key(),
        });
        let err = ready(auth.sign_event_async(unsigned(auth.public_key()))).unwrap_err();
        assert_eq!(err.to_string(), "Signing failed: not available on server");
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn unpolled_future_drops_on_another_thread() {
        let (keys, nc, _) = keyed();
        let fut = nc.sign_event_async(unsigned(keys.public_key()));
        std::thread::scope(|s| s.spawn(move || drop(fut)).join()).unwrap();
    }

    #[cfg(all(feature = "ssr", not(target_arch = "wasm32")))]
    #[test]
    fn server_future_moves_after_suspending() {
        let mut fut = send_future(PendingOnce::new);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        let second = std::thread::scope(|s| {
            s.spawn(move || fut.as_mut().poll(&mut Context::from_waker(Waker::noop())))
                .join()
                .unwrap()
        });
        assert!(second.is_ready());
    }

    #[cfg(all(not(feature = "ssr"), not(target_arch = "wasm32")))]
    #[test]
    fn suspended_future_panics_on_another_thread() {
        let mut fut = send_future(PendingOnce::new);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        let payload = std::thread::scope(|s| {
            s.spawn(move || fut.as_mut().poll(&mut Context::from_waker(Waker::noop())))
                .join()
                .unwrap_err()
        });
        let text = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap();
        assert!(text.contains("Polling SendWrapper<T> variable from a thread different"));
    }
}
