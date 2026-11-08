use nostr::key::PublicKey;

use crate::signers::{
    BunkerSession, Nip07Handle, PasskeySession, PendingPasskey, ReadOnlyHandle, public_key_from_hex,
};
use crate::types::{AuthResult, LoginMethod, NostrAuthError, PersistedMethod, PersistedSession};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestorePlan {
    Nothing,
    /// The stored method left `allowed_methods`. No prompt, no network, session kept.
    NotAllowed,
    Restore,
    /// A stored passkey, which restores only from the login click. No prompt, session kept.
    AwaitClick,
}

pub fn restore_plan(
    persist: bool,
    stored: Option<&PersistedSession>,
    allowed: &[LoginMethod],
) -> RestorePlan {
    match stored {
        Some(session) if persist => {
            if !allowed.contains(&session.method.login_method()) {
                RestorePlan::NotAllowed
            } else if session.method == PersistedMethod::Passkey {
                RestorePlan::AwaitClick
            } else {
                RestorePlan::Restore
            }
        }
        _ => RestorePlan::Nothing,
    }
}

/// Server HTML cannot know storage, so a hydrated first render must start false.
pub fn initial_restoring(hydrating: bool, plan: RestorePlan) -> bool {
    !hydrating && plan == RestorePlan::Restore
}

pub enum LoginStorageAction {
    Keep,
    Overwrite {
        session: PersistedSession,
        /// Another identity is stored, and a failed write would let it return on reload.
        clear_on_failure: bool,
    },
    Clear,
}

/// Keys compare parsed, so an unparseable stored key counts as a different identity.
pub fn login_storage_action(
    persist: bool,
    stored: Option<&PersistedSession>,
    next_public_key: &PublicKey,
    next_persisted: Option<PersistedSession>,
) -> LoginStorageAction {
    if !persist {
        return LoginStorageAction::Keep;
    }
    let other_identity_stored = stored.is_some_and(|session| {
        PublicKey::from_hex(&session.public_key_hex).ok().as_ref() != Some(next_public_key)
    });
    match next_persisted {
        Some(session) => LoginStorageAction::Overwrite {
            session,
            clear_on_failure: other_identity_stored,
        },
        None if other_identity_stored => LoginStorageAction::Clear,
        None => LoginStorageAction::Keep,
    }
}

pub fn is_logout_storage_event(
    persist: bool,
    is_local_area: bool,
    event_key: Option<&str>,
    new_value: Option<&str>,
    storage_key: &str,
) -> bool {
    if !persist || !is_local_area {
        return false;
    }
    // `key == None` must not consult `stored_session`: upstream's listener runs first, and the
    // microtask checkpoint between listeners of a real storage event has already refetched it.
    event_key.is_none_or(|key| key == storage_key && new_value.is_none())
}

pub fn passkey_restore_target(
    session: &PersistedSession,
) -> Result<(PublicKey, Vec<u8>), NostrAuthError> {
    let stored_pk = public_key_from_hex(&session.public_key_hex)?;
    let cred_id_b64 = session
        .passkey_credential_id
        .as_deref()
        .ok_or_else(|| NostrAuthError::PasskeyFailed("no credential ID stored".into()))?;
    let cred_id = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        cred_id_b64,
    )
    .map_err(|e| NostrAuthError::PasskeyFailed(e.to_string()))?;
    Ok((stored_pk, cred_id))
}

/// A passkey restore whose `get` has already started.
pub struct PendingRestore {
    pending: PendingPasskey,
    stored_pk: PublicKey,
}

impl PendingRestore {
    pub async fn finish(self) -> Result<AuthResult, NostrAuthError> {
        let session = self.pending.finish().await?;
        if session.public_key != self.stored_pk {
            return Err(NostrAuthError::SignerKeyMismatch);
        }
        Ok(AuthResult::Passkey(session))
    }
}

/// Start a passkey restore now, so that its `get` runs inside the caller's click handler.
pub fn begin_passkey_restore(
    session: &PersistedSession,
    rp_id: &str,
) -> Result<PendingRestore, NostrAuthError> {
    let (stored_pk, cred_id) = passkey_restore_target(session)?;
    let pending = PasskeySession::begin_authenticate(rp_id, Some(&cred_id))?;
    Ok(PendingRestore { pending, stored_pk })
}

/// Restore a stored session. A passkey fails closed, never prompting; see
/// [`begin_passkey_restore`].
pub async fn restore_session(
    session: &PersistedSession,
    bunker_timeout_secs: u32,
) -> Result<AuthResult, NostrAuthError> {
    let stored_pk = public_key_from_hex(&session.public_key_hex)?;

    match session.method {
        PersistedMethod::Extension => {
            let handle = Nip07Handle::get_public_key().await?;
            if handle.public_key != stored_pk {
                return Err(NostrAuthError::SignerKeyMismatch);
            }
            Ok(AuthResult::Extension(handle))
        }
        PersistedMethod::Bunker => {
            let uri = session
                .bunker_uri
                .as_deref()
                .ok_or_else(|| NostrAuthError::InvalidBunkerUri("no URI stored".into()))?;
            let client_secret_hex = session
                .bunker_client_secret_hex
                .as_deref()
                .ok_or_else(|| NostrAuthError::InvalidBunkerUri("no session key stored".into()))?;
            let session =
                BunkerSession::reconnect(uri, bunker_timeout_secs, client_secret_hex).await?;
            if session.public_key != stored_pk {
                return Err(NostrAuthError::SignerKeyMismatch);
            }
            Ok(AuthResult::Bunker(Box::new(session)))
        }
        PersistedMethod::Passkey => {
            // Reached only by a plan bug. A prompt here would have no user gesture.
            passkey_restore_target(session)?;
            Err(NostrAuthError::PasskeyFailed(
                "a passkey restores only from the login click".into(),
            ))
        }
        PersistedMethod::ReadOnly => Ok(AuthResult::ReadOnly(ReadOnlyHandle {
            public_key: stored_pk,
        })),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests assert by unwrapping and panicking"
)]
pub mod tests {
    use super::*;
    use codee::Decoder;
    use codee::string::JsonSerdeCodec;
    use core::future::Future;
    use core::pin::pin;
    use core::sync::atomic::{AtomicBool, Ordering};
    use core::task::{Context, Poll, Waker};
    use futures::future::{AbortHandle, Abortable};
    use std::sync::Arc;

    const USER: &str = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2";
    const OTHER: &str = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";
    const OFF_CURVE: &str = "eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34";

    pub fn first_poll<F: Future>(fut: F) -> Option<F::Output> {
        match pin!(fut).poll(&mut Context::from_waker(Waker::noop())) {
            Poll::Ready(out) => Some(out),
            Poll::Pending => None,
        }
    }

    fn session(pk: &str, method: PersistedMethod) -> PersistedSession {
        PersistedSession {
            public_key_hex: pk.to_owned(),
            method,
            bunker_uri: None,
            bunker_client_secret_hex: None,
            passkey_credential_id: None,
        }
    }

    fn user_key() -> PublicKey {
        PublicKey::from_hex(USER).unwrap()
    }

    fn action(
        persist: bool,
        stored: Option<&PersistedSession>,
        next: Option<PersistedSession>,
    ) -> LoginStorageAction {
        login_storage_action(persist, stored, &user_key(), next)
    }

    fn restore_err(s: &PersistedSession) -> NostrAuthError {
        match first_poll(restore_session(s, 1)) {
            Some(Err(e)) => e,
            Some(Ok(_)) => panic!("restored"),
            None => panic!("went to the network or a prompt"),
        }
    }

    const METHODS: [PersistedMethod; 4] = [
        PersistedMethod::Extension,
        PersistedMethod::Bunker,
        PersistedMethod::Passkey,
        PersistedMethod::ReadOnly,
    ];

    #[test]
    fn never_restorable_bad_pubkey_each_method() {
        for method in METHODS {
            assert!(matches!(
                restore_err(&session("zz", method)),
                NostrAuthError::InvalidPublicKey(_)
            ));
        }
    }

    #[test]
    fn never_restorable_off_curve_each_method() {
        for method in METHODS {
            assert!(matches!(
                restore_err(&session(OFF_CURVE, method)),
                NostrAuthError::InvalidPublicKey(_)
            ));
        }
    }

    #[test]
    fn never_restorable_missing_uri() {
        let s = PersistedSession {
            bunker_client_secret_hex: Some("44".repeat(32)),
            ..session(USER, PersistedMethod::Bunker)
        };
        assert!(matches!(
            restore_err(&s),
            NostrAuthError::InvalidBunkerUri(_)
        ));
    }

    #[test]
    fn never_restorable_missing_secret() {
        let s = PersistedSession {
            bunker_uri: Some(format!("bunker://{OTHER}?relay=wss%3A%2F%2Fr.example")),
            ..session(USER, PersistedMethod::Bunker)
        };
        assert!(matches!(
            restore_err(&s),
            NostrAuthError::InvalidBunkerUri(_)
        ));
    }

    #[test]
    fn never_restorable_missing_credential() {
        assert!(matches!(
            restore_err(&session(USER, PersistedMethod::Passkey)),
            NostrAuthError::PasskeyFailed(_)
        ));
    }

    #[test]
    fn never_restorable_bad_base64() {
        let s = PersistedSession {
            passkey_credential_id: Some("!!!".to_owned()),
            ..session(USER, PersistedMethod::Passkey)
        };
        assert!(matches!(restore_err(&s), NostrAuthError::PasskeyFailed(_)));
    }

    #[cfg(not(feature = "ssr"))]
    #[test]
    fn never_restorable_bad_client_secret() {
        let s = PersistedSession {
            bunker_uri: Some(format!("bunker://{OTHER}?relay=wss%3A%2F%2Fr.example")),
            bunker_client_secret_hex: Some("zz".to_owned()),
            ..session(USER, PersistedMethod::Bunker)
        };
        assert!(matches!(
            restore_err(&s),
            NostrAuthError::BunkerConnectionFailed(_)
        ));
    }

    #[cfg(not(feature = "ssr"))]
    #[test]
    fn never_restorable_bad_uri() {
        let s = PersistedSession {
            bunker_uri: Some("notauri".to_owned()),
            bunker_client_secret_hex: Some("44".repeat(32)),
            ..session(USER, PersistedMethod::Bunker)
        };
        assert!(matches!(
            restore_err(&s),
            NostrAuthError::InvalidBunkerUri(_)
        ));
    }

    #[cfg(not(feature = "ssr"))]
    #[test]
    fn restore_error_text_quotes_no_stored_secret() {
        const SENTINEL: &str = "SENTINELSECRET";
        let cases = [
            (
                Some(format!("bunker://{OTHER}?relay=wss%3A%2F%2Fr.example")),
                Some(SENTINEL.to_owned()),
            ),
            (Some(format!("bunker://{SENTINEL}")), Some("44".repeat(32))),
            (None, Some(SENTINEL.to_owned())),
        ];
        for (bunker_uri, bunker_client_secret_hex) in cases {
            let s = PersistedSession {
                bunker_uri,
                bunker_client_secret_hex,
                ..session(USER, PersistedMethod::Bunker)
            };
            let e = restore_err(&s);
            assert!(!e.to_string().contains(SENTINEL));
            assert!(!format!("{e:?}").contains(SENTINEL));
        }
    }

    fn passkey_session(pk: &str, id: Option<&str>) -> PersistedSession {
        PersistedSession {
            passkey_credential_id: id.map(str::to_owned),
            ..session(pk, PersistedMethod::Passkey)
        }
    }

    #[test]
    fn passkey_target_bad_key() {
        assert!(matches!(
            passkey_restore_target(&passkey_session("zz", Some("AAEC"))),
            Err(NostrAuthError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn passkey_target_off_curve() {
        assert!(matches!(
            passkey_restore_target(&passkey_session(OFF_CURVE, Some("AAEC"))),
            Err(NostrAuthError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn passkey_target_missing_id() {
        assert!(matches!(
            passkey_restore_target(&passkey_session(USER, None)),
            Err(NostrAuthError::PasskeyFailed(_))
        ));
    }

    #[test]
    fn passkey_target_bad_base64() {
        assert!(matches!(
            passkey_restore_target(&passkey_session(USER, Some("!!!"))),
            Err(NostrAuthError::PasskeyFailed(_))
        ));
    }

    #[test]
    fn passkey_target_decodes_base64url() {
        let (pk, id) = passkey_restore_target(&passkey_session(USER, Some("-_-_"))).unwrap();
        assert_eq!(pk, user_key());
        assert_eq!(id, [0xfb, 0xff, 0xbf]);
    }

    // A browser call would panic on the default native run, so its kill counts only there.
    #[test]
    fn restore_session_never_prompts_for_passkey() {
        let e = restore_err(&passkey_session(USER, Some("AAEC")));
        assert!(e.to_string().contains("login click"));
    }

    #[test]
    fn undecodable_json_is_an_error() {
        assert!(
            <JsonSerdeCodec as Decoder<Option<PersistedSession>>>::decode("not json{").is_err()
        );
    }

    #[test]
    fn persistable_login_overwrites() {
        let next = session(USER, PersistedMethod::ReadOnly);
        let cases = [
            (None, false),
            (Some(session(USER, PersistedMethod::Extension)), false),
            (Some(session(OTHER, PersistedMethod::Extension)), true),
            (Some(session("zz", PersistedMethod::Extension)), true),
        ];
        for (stored, want) in cases {
            match action(true, stored.as_ref(), Some(next.clone())) {
                LoginStorageAction::Overwrite {
                    session,
                    clear_on_failure,
                } => {
                    assert_eq!(session, next);
                    assert_eq!(clear_on_failure, want);
                }
                _ => panic!("not an overwrite"),
            }
        }
    }

    #[test]
    fn nonpersistable_same_key_keeps() {
        let stored = session(USER, PersistedMethod::Extension);
        assert!(matches!(
            action(true, Some(&stored), None),
            LoginStorageAction::Keep
        ));
    }

    #[test]
    fn nonpersistable_uppercase_hex_is_same() {
        let stored = session(&USER.to_uppercase(), PersistedMethod::Extension);
        assert!(matches!(
            action(true, Some(&stored), None),
            LoginStorageAction::Keep
        ));
    }

    #[test]
    fn nonpersistable_different_clears() {
        let stored = session(OTHER, PersistedMethod::Extension);
        assert!(matches!(
            action(true, Some(&stored), None),
            LoginStorageAction::Clear
        ));
    }

    #[test]
    fn nonpersistable_unparseable_is_different() {
        let stored = session("zz", PersistedMethod::Extension);
        assert!(matches!(
            action(true, Some(&stored), None),
            LoginStorageAction::Clear
        ));
    }

    #[test]
    fn nothing_stored_keeps() {
        assert!(matches!(action(true, None, None), LoginStorageAction::Keep));
    }

    #[test]
    fn persist_off_never_writes() {
        let stored = session(OTHER, PersistedMethod::Extension);
        let next = session(USER, PersistedMethod::ReadOnly);
        for (s, n) in [
            (Some(&stored), Some(next.clone())),
            (Some(&stored), None),
            (None, Some(next)),
        ] {
            assert!(matches!(action(false, s, n), LoginStorageAction::Keep));
        }
    }

    #[test]
    fn removed_method_is_not_allowed() {
        for method in METHODS {
            let s = session(USER, method.clone());
            let without: Vec<_> = LoginMethod::all()
                .into_iter()
                .filter(|m| *m != method.login_method())
                .collect();
            assert_eq!(
                restore_plan(true, Some(&s), &without),
                RestorePlan::NotAllowed
            );
            let want = if method == PersistedMethod::Passkey {
                RestorePlan::AwaitClick
            } else {
                RestorePlan::Restore
            };
            assert_eq!(restore_plan(true, Some(&s), &LoginMethod::all()), want);
        }
    }

    #[test]
    fn persist_off_plan_is_nothing() {
        let s = session(USER, PersistedMethod::Bunker);
        assert_eq!(
            restore_plan(false, Some(&s), &LoginMethod::all()),
            RestorePlan::Nothing
        );
        assert_eq!(
            restore_plan(true, None, &LoginMethod::all()),
            RestorePlan::Nothing
        );
    }

    #[test]
    fn initial_restoring_table() {
        for (hydrating, plan, want) in [
            (false, RestorePlan::Restore, true),
            (false, RestorePlan::NotAllowed, false),
            (false, RestorePlan::Nothing, false),
            (true, RestorePlan::Restore, false),
            (true, RestorePlan::NotAllowed, false),
            (true, RestorePlan::Nothing, false),
            (false, RestorePlan::AwaitClick, false),
            (true, RestorePlan::AwaitClick, false),
        ] {
            assert_eq!(initial_restoring(hydrating, plan), want);
        }
    }

    #[test]
    fn logout_event_table() {
        const K: &str = "key";
        let on = |key, value| is_logout_storage_event(true, true, key, value, K);
        assert!(on(Some(K), None));
        assert!(on(None, None));
        assert!(!on(Some("other"), None));
        assert!(!on(Some(K), Some("value")));
        assert!(!is_logout_storage_event(false, true, Some(K), None, K));
        assert!(!is_logout_storage_event(false, true, None, None, K));
        assert!(!is_logout_storage_event(true, false, Some(K), None, K));
        assert!(!is_logout_storage_event(true, false, None, None, K));
    }

    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn aborted_restore_never_lands() {
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = DropFlag(Arc::clone(&dropped));
        let (handle, registration) = AbortHandle::new_pair();
        let mut fut = Box::pin(Abortable::new(
            async move {
                let _flag = flag;
                futures::future::pending::<u8>().await
            },
            registration,
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        handle.abort();
        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Ready(Err(_))));
        drop(fut);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn abort_before_first_poll_never_starts() {
        let started = Arc::new(AtomicBool::new(false));
        let inner = Arc::clone(&started);
        let (handle, registration) = AbortHandle::new_pair();
        let fut = Abortable::new(
            async move {
                inner.store(true, Ordering::SeqCst);
            },
            registration,
        );
        handle.abort();
        assert!(matches!(first_poll(fut), Some(Err(_))));
        assert!(!started.load(Ordering::SeqCst));
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    const USER: &str = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2";
    const OTHER: &str = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

    fn extension_session() -> PersistedSession {
        PersistedSession {
            public_key_hex: USER.to_owned(),
            method: PersistedMethod::Extension,
            bunker_uri: None,
            bunker_client_secret_hex: None,
            passkey_credential_id: None,
        }
    }

    fn shim(pk: &str) {
        js_sys::eval(&format!(
            "globalThis.window = {{ nostr: {{ getPublicKey: function () {{ return Promise.resolve('{pk}'); }} }} }};"
        ))
        .unwrap();
    }

    #[wasm_bindgen_test]
    async fn extension_other_key_is_a_mismatch() {
        shim(OTHER);
        assert!(matches!(
            restore_session(&extension_session(), 1).await,
            Err(NostrAuthError::SignerKeyMismatch)
        ));
    }

    #[wasm_bindgen_test]
    async fn extension_off_curve_on_restore_is_invalid() {
        shim("eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34");
        let got = restore_session(&extension_session(), 1).await.map(|_| ());
        assert!(
            matches!(
                &got,
                Err(NostrAuthError::InvalidPublicKey(m))
                    if m == "the extension returned an invalid public key"
            ),
            "{got:?}"
        );
    }

    #[wasm_bindgen_test]
    async fn extension_non_string_on_restore_is_rejected() {
        js_sys::eval(
            "globalThis.window = { nostr: { getPublicKey: function () { return Promise.resolve(null); } } };",
        )
        .unwrap();
        let got = restore_session(&extension_session(), 1).await.map(|_| ());
        assert!(
            matches!(
                &got,
                Err(NostrAuthError::ExtensionRejected(m)) if m == "expected string pubkey"
            ),
            "{got:?}"
        );
    }

    #[wasm_bindgen_test]
    async fn extension_matching_key_restores() {
        shim(USER);
        assert!(matches!(
            restore_session(&extension_session(), 1).await,
            Ok(AuthResult::Extension(_))
        ));
    }

    #[wasm_bindgen_test]
    async fn extension_absent_is_not_found() {
        js_sys::eval("delete globalThis.window;").unwrap();
        assert!(matches!(
            restore_session(&extension_session(), 1).await,
            Err(NostrAuthError::ExtensionNotFound)
        ));
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod tampered_bunker {
    use super::*;
    use crate::signers::test_ws;
    use core::cell::RefCell;
    use nostr::event::{FinalizeEvent as _, Kind, Tag, UnsignedEvent};
    use nostr::key::Keys;
    use nostr::message::{ClientMessage, RelayMessage, SubscriptionId};
    use nostr::nips::nip44;
    use nostr::nips::nip46::{NostrConnectMessage, NostrConnectMethod};
    use nostr::types::Timestamp;
    use std::rc::Rc;
    use wasm_bindgen_test::wasm_bindgen_test;

    const VICTIM: &str = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2";

    type Log = Rc<RefCell<Vec<NostrConnectMethod>>>;

    enum Answers {
        /// Every result is the victim's public key, without holding the victim's key.
        VictimKeyOnly,
        Holds(Keys),
    }

    impl Answers {
        fn result(&self, method: NostrConnectMethod, params: &[String]) -> String {
            let Self::Holds(user) = self else {
                return VICTIM.to_owned();
            };
            let param = |i: usize| params.get(i).unwrap();
            match method {
                NostrConnectMethod::SignEvent => UnsignedEvent::from_json(param(0))
                    .unwrap()
                    .finalize(user)
                    .unwrap()
                    .as_json(),
                NostrConnectMethod::Nip44Encrypt => nip44::encrypt(
                    user.secret_key(),
                    &PublicKey::from_hex(param(0)).unwrap(),
                    param(1),
                    nip44::Version::V2,
                )
                .unwrap(),
                _ => user.public_key().to_hex(),
            }
        }
    }

    async fn fake_signer(remote: Keys, client: PublicKey, answers: Answers, methods: Log) {
        loop {
            test_ws::tick(10).await;
            for ws in test_ws::sockets().iter() {
                for frame in test_ws::take_sent(&ws) {
                    let Ok(ClientMessage::Event(event)) = ClientMessage::from_json(&frame) else {
                        continue;
                    };
                    let plain =
                        nip44::decrypt(remote.secret_key(), &event.pubkey, &event.content).unwrap();
                    let NostrConnectMessage::Request { id, method, params } =
                        NostrConnectMessage::from_json(&plain).unwrap()
                    else {
                        continue;
                    };
                    let result = answers.result(method, &params);
                    methods.borrow_mut().push(method);
                    let reply = serde_json::json!({ "id": id, "result": result }).to_string();
                    let content =
                        nip44::encrypt(remote.secret_key(), &client, reply, nip44::Version::V2)
                            .unwrap();
                    let answer = UnsignedEvent::new(
                        remote.public_key(),
                        Timestamp::from_secs(1_700_000_000),
                        Kind::NostrConnect,
                        [Tag::public_key(client)],
                        content,
                    )
                    .finalize(&remote)
                    .unwrap();
                    let msg = RelayMessage::event(SubscriptionId::new("nip46-persistent"), answer)
                        .as_json();
                    test_ws::deliver(&ws, &msg);
                }
            }
        }
    }

    fn stored(user_hex: &str, remote: &Keys, client: &Keys) -> PersistedSession {
        PersistedSession {
            public_key_hex: user_hex.to_owned(),
            method: PersistedMethod::Bunker,
            bunker_uri: Some(format!(
                "bunker://{}?relay=wss%3A%2F%2Fsigner.example",
                remote.public_key().to_hex()
            )),
            bunker_client_secret_hex: Some(client.secret_key().to_secret_hex()),
            passkey_credential_id: None,
        }
    }

    fn bunker(result: Result<AuthResult, NostrAuthError>) -> BunkerSession {
        match result {
            Ok(AuthResult::Bunker(session)) => *session,
            Ok(_) => unreachable!("restored another method"),
            Err(e) => unreachable!("restore failed: {e}"),
        }
    }

    #[wasm_bindgen_test]
    async fn unproven_bunker_never_receives_nip44_plaintext() {
        test_ws::install();
        let attacker = Keys::generate();
        let client = Keys::generate();
        let stored = stored(VICTIM, &attacker, &client);
        let methods = Log::default();
        let signer = fake_signer(
            attacker,
            client.public_key(),
            Answers::VictimKeyOnly,
            Rc::clone(&methods),
        );
        let body = async {
            if let Ok(session) = restore_session(&stored, 2).await {
                let peer = Keys::generate().public_key();
                let got = session.nip44_encrypt(&peer, "meet at nine").await;
                assert!(
                    got.is_err(),
                    "encrypted through a signer without the key: {got:?}"
                );
            }
        };
        futures::pin_mut!(signer, body);
        futures::future::select(body, signer).await;
        assert!(
            !methods.borrow().contains(&NostrConnectMethod::Nip44Encrypt),
            "plaintext reached a signer that never proved the key: {:?}",
            methods.borrow()
        );
    }

    #[wasm_bindgen_test]
    async fn proof_runs_once_then_nip44_goes_through() {
        test_ws::install();
        let remote = Keys::generate();
        let client = Keys::generate();
        let victim = Keys::generate();
        let stored = stored(&victim.public_key().to_hex(), &remote, &client);
        let methods = Log::default();
        let signer = fake_signer(
            remote,
            client.public_key(),
            Answers::Holds(victim),
            Rc::clone(&methods),
        );
        let body = async {
            let session = bunker(restore_session(&stored, 2).await);
            let peer = Keys::generate().public_key();
            let got = session.nip44_encrypt(&peer, "a").await;
            assert!(got.is_ok(), "{got:?}");
            assert_eq!(
                *methods.borrow(),
                [
                    NostrConnectMethod::GetPublicKey,
                    NostrConnectMethod::SignEvent,
                    NostrConnectMethod::Nip44Encrypt
                ]
            );
            let again = session.nip44_encrypt(&peer, "b").await;
            assert!(again.is_ok(), "{again:?}");
            assert_eq!(
                methods.borrow().get(3..),
                Some(&[NostrConnectMethod::Nip44Encrypt][..])
            );
        };
        futures::pin_mut!(signer, body);
        futures::future::select(body, signer).await;
    }

    #[wasm_bindgen_test]
    async fn concurrent_nip44_calls_share_one_proof() {
        test_ws::install();
        let remote = Keys::generate();
        let client = Keys::generate();
        let victim = Keys::generate();
        let stored = stored(&victim.public_key().to_hex(), &remote, &client);
        let methods = Log::default();
        let signer = fake_signer(
            remote,
            client.public_key(),
            Answers::Holds(victim),
            Rc::clone(&methods),
        );
        let body = async {
            let session = bunker(restore_session(&stored, 2).await);
            let peer = Keys::generate().public_key();
            let (a, b) = futures::future::join(
                session.nip44_encrypt(&peer, "a"),
                session.nip44_encrypt(&peer, "b"),
            )
            .await;
            assert!(a.is_ok() && b.is_ok(), "{a:?} {b:?}");
            let signs = methods
                .borrow()
                .iter()
                .filter(|m| **m == NostrConnectMethod::SignEvent)
                .count();
            assert_eq!(
                signs,
                1,
                "one challenge per session: {:?}",
                methods.borrow()
            );
        };
        futures::pin_mut!(signer, body);
        futures::future::select(body, signer).await;
    }
}
