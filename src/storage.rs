use nostr::key::PublicKey;

use crate::signers::{BunkerSession, Nip07Handle, PasskeySession, ReadOnlyHandle};
use crate::types::{AuthResult, LoginMethod, NostrAuthError, PersistedMethod, PersistedSession};

/// What the provider does about a stored session on mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RestorePlan {
    Nothing,
    NotAllowed,
    Restore,
}

pub(crate) fn restore_plan(
    persist: bool,
    stored: Option<&PersistedSession>,
    allowed: &[LoginMethod],
) -> RestorePlan {
    match stored {
        Some(session) if persist => {
            if allowed.contains(&session.method.login_method()) {
                RestorePlan::Restore
            } else {
                RestorePlan::NotAllowed
            }
        }
        _ => RestorePlan::Nothing,
    }
}

/// Server HTML cannot know storage, so a hydrated first render must start false.
pub(crate) fn initial_restoring(hydrating: bool, plan: RestorePlan) -> bool {
    !hydrating && plan == RestorePlan::Restore
}

/// What a successful login does to the stored session.
pub(crate) enum LoginStorageAction {
    Keep,
    /// `clear_on_failure` is set when something else is stored, because a failed write would leave
    /// that other identity to return on reload.
    Overwrite {
        session: PersistedSession,
        clear_on_failure: bool,
    },
    Clear,
}

pub(crate) fn login_storage_action(
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

/// Whether a `storage` event means another tab removed the stored session.
pub(crate) fn is_logout_storage_event(
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
    match event_key {
        None => true,
        Some(key) => key == storage_key && new_value.is_none(),
    }
}

/// Attempt to restore a full `AuthResult` from a `PersistedSession`.
///
/// Save/load/clear are handled by the `use_local_storage` hook in `NostrAuthProvider`.
///
/// Each method has different restore semantics:
/// - `Extension`: verify window.nostr still returns the same pubkey
/// - `Bunker`: re-establish WebSocket connection using stored bunker URI
/// - `Passkey`: call `navigator.credentials.get()` → PRF → rederive key
/// - `ReadOnly`: restore directly from hex pubkey (no re-auth needed)
pub async fn restore_session(
    session: &PersistedSession,
    bunker_timeout_secs: u32,
) -> Result<AuthResult, NostrAuthError> {
    let stored_pk = PublicKey::from_hex(&session.public_key_hex)
        .map_err(|e| NostrAuthError::InvalidPublicKey(e.to_string()))?;

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
            let cred_id_b64 = session
                .passkey_credential_id
                .as_deref()
                .ok_or_else(|| NostrAuthError::PasskeyFailed("no credential ID stored".into()))?;
            let cred_id = base64::Engine::decode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                cred_id_b64,
            )
            .map_err(|e| NostrAuthError::PasskeyFailed(e.to_string()))?;
            let ps = PasskeySession::authenticate(Some(cred_id)).await?;
            if ps.public_key != stored_pk {
                return Err(NostrAuthError::SignerKeyMismatch);
            }
            Ok(AuthResult::Passkey(ps))
        }
        PersistedMethod::ReadOnly => Ok(AuthResult::ReadOnly(ReadOnlyHandle {
            public_key: stored_pk,
        })),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
pub(crate) mod tests {
    use super::*;
    use codee::Decoder;
    use codee::string::JsonSerdeCodec;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use futures::future::{AbortHandle, Abortable};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const USER: &str = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2";
    const OTHER: &str = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

    pub(crate) fn first_poll<F: Future>(fut: F) -> Option<F::Output> {
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

    #[test]
    fn undecodable_json_is_an_error() {
        assert!(<JsonSerdeCodec as Decoder<Option<PersistedSession>>>::decode("not json{").is_err());
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
        assert!(matches!(
            action(true, None, None),
            LoginStorageAction::Keep
        ));
    }

    #[test]
    fn persist_off_never_writes() {
        let stored = session(OTHER, PersistedMethod::Extension);
        let next = session(USER, PersistedMethod::ReadOnly);
        for (s, n) in [
            (Some(&stored), Some(next.clone())),
            (Some(&stored), None),
            (None, Some(next.clone())),
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
            assert_eq!(
                restore_plan(true, Some(&s), &LoginMethod::all()),
                RestorePlan::Restore
            );
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
