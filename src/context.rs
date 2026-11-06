#![expect(
    clippy::exhaustive_structs,
    reason = "#[component] generates the exported props struct, which cannot take attributes"
)]
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_use_storage::use_local_storage;
use nostr::nips::nip19::ToBech32;

use crate::modal::NostrAuthModal;
use crate::types::{AuthResult, NostrAuthConfig, PersistedSession};

/// Reactive auth context — available anywhere inside [`NostrAuthProvider`].
///
/// Access via [`use_nostr_auth()`] or [`try_use_nostr_auth()`].
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct NostrAuthContext {
    /// Current auth result; `None` when not logged in.
    pub auth: Signal<Option<AuthResult>>,
    /// Convenience: the authenticated user's public key (bech32 npub and hex).
    pub public_key: Signal<Option<nostr::key::PublicKey>>,
    /// Convenience: the authenticated user's npub (bech32) or hex pubkey as a `String`.
    ///
    /// Avoids the common `.to_bech32().unwrap_or_else(|_| .to_hex())` boilerplate.
    pub npub: Signal<Option<String>>,
    /// `true` when a user is logged in.
    pub is_authenticated: Signal<bool>,
    /// `true` while a persisted session is being restored from localStorage on mount.
    ///
    /// Use this to avoid showing a flash of the login button before restore completes.
    pub is_restoring: Signal<bool>,
    /// Open the login modal programmatically.
    pub show_login: Callback<()>,
    /// Log out: clears auth state, removes the localStorage session and closes a bunker session
    /// for good, including for clones kept elsewhere.
    pub logout: Callback<()>,
}

/// Replace the current session, closing the old one for good. Must tolerate a disposed provider:
/// a restore can finish after unmount.
fn replace_auth(
    auth: ReadSignal<Option<AuthResult>>,
    set_auth: WriteSignal<Option<AuthResult>>,
    next: Option<AuthResult>,
) {
    let _ = auth.try_with_untracked(|old| {
        if let Some(old) = old {
            old.close_session();
        }
    });
    set_auth.set(next);
}

/// Retrieve the Nostr auth context.
///
/// # Panics
/// Panics if called outside a [`NostrAuthProvider`] tree.
/// For a non-panicking variant, use [`try_use_nostr_auth()`].
pub fn use_nostr_auth() -> NostrAuthContext {
    #[expect(
        clippy::expect_used,
        reason = "intentional: panics when called outside NostrAuthProvider"
    )]
    use_context::<NostrAuthContext>()
        .expect("`use_nostr_auth` must be called inside a `<NostrAuthProvider>` component")
}

/// Retrieve the Nostr auth context without panicking.
///
/// Returns `None` if called outside a [`NostrAuthProvider`] tree.
pub fn try_use_nostr_auth() -> Option<NostrAuthContext> {
    use_context::<NostrAuthContext>()
}

/// Wraps your application root to provide reactive Nostr authentication state.
///
/// Automatically attempts to restore a cached session from localStorage on mount.
/// Renders [`NostrAuthModal`] internally so you don't need to add it yourself.
///
/// # Example
/// ```rust,ignore
/// fn App() -> impl IntoView {
///     view! {
///         <NostrAuthProvider>
///             <HomePage />
///         </NostrAuthProvider>
///     }
/// }
/// ```
#[component]
pub fn NostrAuthProvider(
    /// Optional configuration (default: all methods enabled, persistence on).
    #[prop(optional)]
    config: Option<NostrAuthConfig>,
    children: Children,
) -> impl IntoView {
    let config = config.unwrap_or_default();
    let cfg = StoredValue::new(config);

    let (auth, set_auth) = signal(None::<AuthResult>);
    let (show_modal, set_show_modal) = signal(false);
    let (restoring, set_restoring) = signal(false);

    // use_local_storage is SSR-safe:
    //   server  → stored_session.get() == None; set/delete are no-ops
    //   client  → reads/writes real localStorage at storage_key
    // PersistedSession requires PartialEq (derived in types.rs) for the equality check
    // that prevents spurious reactive updates.
    let (stored_session, set_stored_session, delete_stored_session) =
        use_local_storage::<Option<PersistedSession>, JsonSerdeCodec>(cfg.get_value().storage_key);

    // Clone before Effect consumes delete_stored_session
    let delete_for_logout = delete_stored_session.clone();

    // On mount: one-time session restore from localStorage.
    // get_untracked() avoids re-running this Effect when the session is saved
    // after a fresh login.
    Effect::new(move |_| {
        if cfg.get_value().persist_session
            && let Some(session) = stored_session.get_untracked()
        {
            set_restoring.set(true);
            let delete = delete_stored_session.clone();
            spawn_local(async move {
                match crate::storage::restore_session(&session, cfg.get_value().bunker_timeout_secs)
                    .await
                {
                    Ok(result) => {
                        replace_auth(auth, set_auth, Some(result));
                    }
                    Err(e) => {
                        web_sys::console::info_1(
                            &format!("leptos-nostr-auth: session restore failed: {e}").into(),
                        );
                        delete();
                    }
                }
                set_restoring.set(false);
            });
        }
    });

    let public_key = Signal::derive(move || auth.get().map(|a| a.public_key()));

    let npub = Signal::derive(move || {
        auth.get().map(|a| {
            let pk = a.public_key();
            pk.to_bech32().unwrap_or_else(|_| pk.to_hex())
        })
    });

    let is_authenticated = Signal::derive(move || auth.get().is_some());

    let show_login = Callback::new(move |(): ()| set_show_modal.set(true));

    let logout = Callback::new(move |(): ()| {
        delete_for_logout(); // SSR-safe no-op on server
        replace_auth(auth, set_auth, None);
    });

    provide_context(NostrAuthContext {
        auth: auth.into(),
        public_key,
        npub,
        is_authenticated,
        is_restoring: restoring.into(),
        show_login,
        logout,
    });

    let on_auth_callback = Callback::new(move |result: AuthResult| {
        // Persist session to localStorage (if configured).
        // set_stored_session is a SSR-safe no-op on server.
        if cfg.get_value().persist_session
            && let Some(session) = result.to_persisted_session()
        {
            set_stored_session.set(Some(session));
        }
        replace_auth(auth, set_auth, Some(result));
        set_show_modal.set(false);
    });

    let on_close_callback = Callback::new(move |(): ()| {
        set_show_modal.set(false);
    });

    view! {
        // Show a subtle loading indicator while restoring (optional — UX polish)
        <Show when=move || restoring.get()>
            <div
                aria-live="polite"
                aria-label="Restoring session…"
                data-nostr-restoring=""
                style="position:fixed;bottom:1rem;right:1rem;z-index:9997;"
            >
                <span data-nostr-spinner="" />
                "Restoring session…"
            </div>
        </Show>

        {children()}

        <NostrAuthModal
            open=Signal::from(show_modal)
            on_auth=on_auth_callback
            on_close=on_close_callback
            config=cfg.get_value()
        />
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod tests {
    use super::*;
    use crate::types::PersistedMethod;
    use codee::{Decoder, Encoder};

    const READ_ONLY_JSON: &str = r#"{"public_key_hex":"82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2","method":"ReadOnly","bunker_uri":null,"bunker_client_secret_hex":null,"passkey_credential_id":null}"#;
    const BUNKER_JSON: &str = r#"{"public_key_hex":"aa","method":"Bunker","bunker_uri":"bunker://bb?relay=wss%3A%2F%2Frelay.example","bunker_client_secret_hex":"cc","passkey_credential_id":null}"#;

    fn read_only() -> PersistedSession {
        PersistedSession {
            public_key_hex: "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2"
                .to_owned(),
            method: PersistedMethod::ReadOnly,
            bunker_uri: None,
            bunker_client_secret_hex: None,
            passkey_credential_id: None,
        }
    }

    fn bunker() -> PersistedSession {
        PersistedSession {
            public_key_hex: "aa".to_owned(),
            method: PersistedMethod::Bunker,
            bunker_uri: Some("bunker://bb?relay=wss%3A%2F%2Frelay.example".to_owned()),
            bunker_client_secret_hex: Some("cc".to_owned()),
            passkey_credential_id: None,
        }
    }

    #[test]
    fn persisted_session_json_format() {
        let enc = |s| JsonSerdeCodec::encode(&Some(s)).unwrap();
        assert_eq!(enc(read_only()), READ_ONLY_JSON);
        assert_eq!(enc(bunker()), BUNKER_JSON);
    }

    #[test]
    fn persisted_session_decodes_stored_literal() {
        let dec = |s| <JsonSerdeCodec as Decoder<Option<PersistedSession>>>::decode(s).unwrap();
        assert_eq!(dec(READ_ONLY_JSON), Some(read_only()));
        assert_eq!(dec(BUNKER_JSON), Some(bunker()));
    }
}
