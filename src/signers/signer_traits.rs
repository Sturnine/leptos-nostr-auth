use core::future::Future;
use core::pin::Pin;

use nostr::event::{AsyncSignEvent, Event, UnsignedEvent};
use nostr::key::{AsyncGetPublicKey, PublicKey};
use nostr::nips::nip44::AsyncNip44;

use crate::types::{AuthResult, NostrAuthError};

/// `SendWrapper` panics on another thread, so it is created at first poll, leaving the future free
/// to move until then. Server futures are `Send` and move between worker threads, so they get none.
#[cfg(not(feature = "ssr"))]
fn send_future<'a, T: 'a, F: Future<Output = T> + 'a>(
    make: impl FnOnce() -> F + Send + 'a,
) -> Pin<Box<dyn Future<Output = T> + Send + 'a>> {
    Box::pin(async move { send_wrapper::SendWrapper::new(make()).await })
}

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
        send_future(
            move || async move { returned_event(self.sign_event(&unsigned.as_json()).await?) },
        )
    }
}

#[expect(
    clippy::map_err_ignore,
    reason = "the serde error text quotes event values"
)]
fn returned_event(json: String) -> Result<Event, NostrAuthError> {
    Event::from_json(json)
        .map_err(|_| NostrAuthError::SigningFailed("signer returned an invalid event".into()))
}

/// Runs through [`AuthResult::nip44_encrypt`] and [`AuthResult::nip44_decrypt`], and returns
/// [`NostrAuthError`] directly. The same thread rule applies as on `AsyncSignEvent`.
///
/// `nostr`'s `nip59` helpers return `nostr::error::Error`. Their NIP-44 steps give kind `Crypto` with
/// the crate's error as source. The seal's signature step gives kind `Other`, also with it as source.
/// Other `nip59` failures, such as an event that is not a gift wrap, have no crate error as source.
/// So use the downcast, not the kind:
/// `err.source().and_then(|s| s.downcast_ref::<NostrAuthError>())`.
///
/// `nip59` is a `nostr` feature, which you enable. On `wasm32-unknown-unknown` the gift-wrap builders
/// reach `Timestamp::now`, which needs `universal_time::define_time_provider!` in your binary. See
/// the README. Unwrapping needs no provider. On an extension each NIP-44 call also calls
/// `getPublicKey`, so an unwrap makes two of each.
impl AsyncNip44 for AuthResult {
    type Error = NostrAuthError;

    fn nip44_encrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        content: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send + 'a>> {
        send_future(move || self.nip44_encrypt(public_key, content))
    }

    fn nip44_decrypt_async<'a>(
        &'a self,
        public_key: &'a PublicKey,
        payload: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, Self::Error>> + Send + 'a>> {
        send_future(move || self.nip44_decrypt(public_key, payload))
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
    use nostr::event::{EventId, FinalizeEvent, FinalizeEventAsync, Kind, Tag};
    use nostr::key::{Keys, SecretKey};
    use nostr::nips::nip44;
    use nostr::types::Timestamp;
    use std::sync::Arc;

    pub(in crate::signers) const UNAVAILABLE: &str = "This session cannot encrypt or decrypt: it is read-only, or its signer is only reachable in the browser";
    const VECTOR: &str = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb";

    // BIP-340's not-on-curve vector, which `from_hex` accepts.
    pub(in crate::signers) fn off_curve() -> PublicKey {
        let key =
            PublicKey::from_hex("eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34")
                .unwrap();
        assert!(key.xonly().is_err());
        key
    }

    fn key_sessions(keys: &Keys) -> Vec<AuthResult> {
        vec![
            AuthResult::Ncryptsec(RawKeySession::for_tests(keys.clone())),
            AuthResult::Passkey(PasskeySession::for_tests(keys.clone(), vec![1])),
        ]
    }

    fn nonce_of(ciphertext: &str) -> Vec<u8> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(ciphertext)
            .unwrap();
        assert_eq!(bytes.first(), Some(&2));
        bytes.get(1..33).unwrap().to_vec()
    }

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
            + AsyncNip44<Error = NostrAuthError>
            + Send
            + Sync,
    >(
        _: &S,
    ) {
    }

    fn assert_send<T: Send>(_: T) {}

    #[test]
    fn invalid_returned_event_quotes_no_text() {
        let err = returned_event(r#"{"kind":"secret-kind"}"#.into()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "Signing failed: signer returned an invalid event"
        );
    }

    #[test]
    fn auth_result_is_send_sync_nostr_signer() {
        let (keys, nc, _) = keyed();
        assert_signer(&nc);
        assert_send(nc.get_public_key_async());
        assert_send(nc.sign_event_async(unsigned(keys.public_key())));
        assert_send(nc.nip44_encrypt_async(&keys.public_key(), "x"));
        assert_send(nc.nip44_decrypt_async(&keys.public_key(), "x"));
        let _: Arc<dyn AsyncNip44<Error = NostrAuthError>> = Arc::new(nc.clone());
        let _: Arc<dyn AsyncSignEvent<Error = NostrAuthError>> = Arc::new(nc);
    }

    #[test]
    fn nip44_round_trip_each_key_variant() {
        let (a, nc, _) = keyed();
        let (b, _, pk) = keyed();
        let forward = ready(nc.nip44_encrypt(&b.public_key(), "hello")).unwrap();
        assert_eq!(
            ready(pk.nip44_decrypt(&a.public_key(), &forward)).unwrap(),
            "hello"
        );
        assert_eq!(
            nip44::decrypt(b.secret_key(), &a.public_key(), &forward).unwrap(),
            "hello"
        );
        let back = ready(pk.nip44_encrypt(&a.public_key(), "back")).unwrap();
        assert_eq!(
            ready(nc.nip44_decrypt(&b.public_key(), &back)).unwrap(),
            "back"
        );
        assert_eq!(
            nip44::decrypt(a.secret_key(), &b.public_key(), &back).unwrap(),
            "back"
        );
    }

    #[cfg(feature = "insecure_nsec_input")]
    #[test]
    fn nip44_round_trip_raw_nsec() {
        let a = Keys::generate();
        let b = Keys::generate();
        let raw = AuthResult::RawNsec(RawKeySession::for_tests(a.clone()));
        let ct = ready(raw.nip44_encrypt(&b.public_key(), "hello")).unwrap();
        assert_eq!(
            nip44::decrypt(b.secret_key(), &a.public_key(), &ct).unwrap(),
            "hello"
        );
        let back =
            nip44::encrypt(b.secret_key(), &a.public_key(), "back", nip44::Version::V2).unwrap();
        assert_eq!(
            ready(raw.nip44_decrypt(&b.public_key(), &back)).unwrap(),
            "back"
        );
    }

    #[test]
    fn nip44_known_vector() {
        let secret = |last: char| {
            let hex = format!("{}{last}", "0".repeat(63));
            Keys::new(SecretKey::from_hex(&hex).unwrap())
        };
        let (one, two) = (secret('1'), secret('2'));
        for (own, peer) in [(&one, &two), (&two, &one)] {
            for auth in key_sessions(own) {
                assert_eq!(
                    ready(auth.nip44_decrypt(&peer.public_key(), VECTOR)).unwrap(),
                    "a"
                );
            }
        }
    }

    #[test]
    fn nip44_encrypt_is_v2_with_fresh_nonce() {
        let (_, nc, pk) = keyed();
        let peer = Keys::generate().public_key();
        for auth in [nc, pk] {
            let first = ready(auth.nip44_encrypt(&peer, "x")).unwrap();
            let second = ready(auth.nip44_encrypt(&peer, "x")).unwrap();
            assert_ne!(nonce_of(&first), nonce_of(&second));
        }
    }

    #[test]
    fn nip44_read_only_is_typed() {
        let auth = read_only();
        for peer in [Keys::generate().public_key(), off_curve()] {
            for got in [
                ready(auth.nip44_encrypt(&peer, "x")),
                ready(auth.nip44_decrypt(&peer, "x")),
                ready(auth.nip44_encrypt_async(&peer, "x")),
                ready(auth.nip44_decrypt_async(&peer, "x")),
            ] {
                let err = got.unwrap_err();
                assert!(matches!(err, NostrAuthError::EncryptionUnavailable));
                assert_eq!(err.to_string(), UNAVAILABLE);
            }
        }
    }

    // Reaching JS would panic natively, so the extension case also pins the check's place.
    #[test]
    fn nip44_off_curve_peer_is_typed() {
        let (_, nc, pk) = keyed();
        let ext = AuthResult::Extension(Nip07Handle {
            public_key: Keys::generate().public_key(),
        });
        let bad = off_curve();
        #[cfg(feature = "insecure_nsec_input")]
        let raw = AuthResult::RawNsec(RawKeySession::for_tests(Keys::generate()));
        for auth in [
            &nc,
            &pk,
            &ext,
            #[cfg(feature = "insecure_nsec_input")]
            &raw,
        ] {
            let enc = ready(auth.nip44_encrypt(&bad, "x"));
            assert!(matches!(enc, Err(NostrAuthError::InvalidPublicKey(_))));
            let dec = ready(auth.nip44_decrypt(&bad, "x"));
            assert!(matches!(dec, Err(NostrAuthError::InvalidPublicKey(_))));
        }
    }

    #[test]
    fn nip44_failures_are_typed() {
        let (keys, nc, pk) = keyed();
        let other = Keys::generate();
        let good = nip44::encrypt(
            other.secret_key(),
            &keys.public_key(),
            "hi",
            nip44::Version::V2,
        )
        .unwrap();
        let failed = |got: Result<String, NostrAuthError>, want: &str| {
            let err = got.unwrap_err();
            assert!(
                matches!(&err, NostrAuthError::EncryptionFailed(text) if text.contains(want)),
                "{err:?}"
            );
            for shown in [err.to_string(), format!("{err:?}")] {
                assert!(!shown.contains("SENTINEL"), "{shown}");
            }
        };
        let peer = other.public_key();
        let stranger = Keys::generate().public_key();
        for auth in [&nc, &pk] {
            failed(ready(auth.nip44_decrypt(&peer, "SENTINEL!!")), "");
            failed(ready(auth.nip44_decrypt(&peer, "Ag!!")), "");
            failed(ready(auth.nip44_decrypt(&stranger, &good)), "invalid HMAC");
            failed(ready(auth.nip44_decrypt(&peer, "")), "");
            failed(ready(auth.nip44_encrypt(&peer, "")), "message empty");
        }
    }

    #[test]
    fn nip44_non_utf8_plaintext_hides_bytes() {
        let (keys, nc, pk) = keyed();
        let other = Keys::generate();
        let mut plaintext = vec![0xff];
        plaintext.extend_from_slice(b"SENTINEL");
        let payload = nip44::encrypt_with_nonce(
            other.secret_key(),
            &keys.public_key(),
            &plaintext,
            nip44::Nonce::V2([3; 32]),
        )
        .unwrap();
        let run = "83, 69, 78, 84";
        let upstream =
            nip44::decrypt(keys.secret_key(), &other.public_key(), &payload).unwrap_err();
        assert!(format!("{upstream:?}").contains(run));
        for auth in [nc, pk] {
            let err = ready(auth.nip44_decrypt(&other.public_key(), &payload)).unwrap_err();
            assert!(matches!(err, NostrAuthError::EncryptionFailed(_)));
            for shown in [err.to_string(), format!("{err:?}")] {
                assert!(!shown.contains(run), "{shown}");
                assert!(!shown.contains("FromUtf8Error"), "{shown}");
            }
        }
    }

    #[test]
    fn nip44_trait_matches_inherent() {
        let (a, nc, _) = keyed();
        let (b, _, pk) = keyed();
        let sealed = ready(nc.nip44_encrypt_async(&b.public_key(), "hi")).unwrap();
        assert_eq!(
            ready(pk.nip44_decrypt(&a.public_key(), &sealed)).unwrap(),
            "hi"
        );
        let other = ready(pk.nip44_encrypt(&a.public_key(), "yo")).unwrap();
        assert_eq!(
            ready(nc.nip44_decrypt_async(&b.public_key(), &other)).unwrap(),
            "yo"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn gift_wrap_through_auth_result() {
        use nostr::nips::nip59::{GiftWrapBuilder, UnwrappedGift};
        let (keys, nc, _) = keyed();
        let sender = Keys::generate();
        let wrap = GiftWrapBuilder::new(keys.public_key(), unsigned(sender.public_key()))
            .finalize(&sender)
            .unwrap();
        let opened = ready(UnwrappedGift::from_gift_wrap_async(&nc, &wrap)).unwrap();
        assert_eq!(opened.sender, sender.public_key());
        assert_eq!(opened.rumor.content, "hi");

        let reader = Keys::generate();
        let built = ready(
            GiftWrapBuilder::new(reader.public_key(), unsigned(keys.public_key()))
                .finalize_async(&nc),
        )
        .unwrap();
        let read = UnwrappedGift::from_gift_wrap(&reader, &built).unwrap();
        assert_eq!(read.sender, keys.public_key());

        let refused = ready(UnwrappedGift::from_gift_wrap_async(&read_only(), &wrap)).unwrap_err();
        assert_eq!(refused.kind(), ErrorKind::Crypto);
        let source = refused
            .source()
            .and_then(|s| s.downcast_ref::<NostrAuthError>());
        assert!(matches!(
            source,
            Some(NostrAuthError::EncryptionUnavailable)
        ));

        let ro = read_only();
        let unbuilt = ready(
            GiftWrapBuilder::new(reader.public_key(), unsigned(ro.public_key()))
                .finalize_async(&ro),
        )
        .unwrap_err();
        assert_eq!(unbuilt.kind(), ErrorKind::Crypto);
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
    fn keys_refuse_other_pubkey() {
        let keys = Keys::generate();
        let err = unsigned(Keys::generate().public_key()).finalize(&keys);
        assert_eq!(err.unwrap_err().to_string(), "invalid signature");
    }

    #[test]
    fn keys_refuse_wrong_preset_id() {
        let keys = Keys::generate();
        let mut wrong = unsigned(keys.public_key());
        wrong.id = Some(EventId::from_byte_array([7; 32]));
        assert_eq!(
            wrong.finalize(&keys).unwrap_err().to_string(),
            "invalid event ID"
        );
        let mut right = unsigned(keys.public_key());
        let want = right.compute_id();
        right.id = Some(want);
        assert_eq!(right.finalize(&keys).unwrap().id, want);
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
        assert!(
            wrapped
                .to_string()
                .contains("Read-only session cannot sign events")
        );
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
        let source = err
            .source()
            .and_then(|s| s.downcast_ref::<NostrAuthError>());
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

    #[cfg(target_arch = "wasm32")]
    #[cfg(not(feature = "ssr"))]
    mod wasm_tests {
        use super::*;
        use wasm_bindgen_test::wasm_bindgen_test;

        #[wasm_bindgen_test]
        async fn raw_key_finalizes_and_verifies() {
            let (keys, nc, _) = keyed();
            let input = unsigned(keys.public_key());
            let out = input.clone().finalize_async(&nc).await.unwrap();
            assert_fields_equal(&input, &out);
        }

        #[wasm_bindgen_test]
        async fn read_only_is_typed_with_source() {
            let auth = read_only();
            let err = unsigned(auth.public_key())
                .finalize_async(&auth)
                .await
                .unwrap_err();
            let source = err
                .source()
                .and_then(|s| s.downcast_ref::<NostrAuthError>());
            assert!(matches!(source, Some(NostrAuthError::SigningFailed(_))));
        }

        #[wasm_bindgen_test]
        async fn nip44_round_trip_on_wasm() {
            let (a, nc, _) = keyed();
            let (b, _, pk) = keyed();
            let ct = nc.nip44_encrypt(&b.public_key(), "hello").await.unwrap();
            assert_eq!(
                pk.nip44_decrypt(&a.public_key(), &ct).await.unwrap(),
                "hello"
            );
            let traited = pk.nip44_encrypt_async(&a.public_key(), "back").await;
            assert_eq!(
                nc.nip44_decrypt_async(&b.public_key(), &traited.unwrap())
                    .await
                    .unwrap(),
                "back"
            );
        }

        #[wasm_bindgen_test]
        async fn read_only_nip44_is_typed() {
            let auth = read_only();
            let peer = off_curve();
            for got in [
                auth.nip44_encrypt(&peer, "x").await,
                auth.nip44_decrypt(&peer, "x").await,
                auth.nip44_encrypt_async(&peer, "x").await,
                auth.nip44_decrypt_async(&peer, "x").await,
            ] {
                assert_eq!(got.unwrap_err().to_string(), UNAVAILABLE);
            }
        }

        #[wasm_bindgen_test]
        async fn nip44_nonce_comes_from_get_random_values() {
            let (_, nc, _) = keyed();
            let peer = Keys::generate().public_key();
            js_sys::eval(
                "globalThis.__rng = 0; Object.defineProperty(globalThis.crypto, 'getRandomValues', { configurable: true, value: (a) => { globalThis.__rng += 1; a.fill(0xAB); return a; } });",
            )
            .unwrap();
            let spied = nc.nip44_encrypt(&peer, "x").await.unwrap();
            let count = js_sys::eval("globalThis.__rng").unwrap().as_f64().unwrap();
            js_sys::eval("delete globalThis.crypto.getRandomValues;").unwrap();
            assert!(count >= 1.0);
            assert_eq!(nonce_of(&spied), vec![0xAB; 32]);
            let plain = nc.nip44_encrypt(&peer, "x").await.unwrap();
            assert_ne!(nonce_of(&plain), vec![0xAB; 32]);
        }

        #[wasm_bindgen_test]
        async fn get_public_key_async_returns_session_key() {
            let (keys, nc, _) = keyed();
            assert_eq!(nc.get_public_key_async().await.unwrap(), keys.public_key());
        }
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
