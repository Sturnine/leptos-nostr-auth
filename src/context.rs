// The #[component] macro generates exhaustive props structs that we cannot add
// #[non_exhaustive] to. Suppressed here since real public types use it explicitly.
#![allow(clippy::exhaustive_structs)]
use codee::string::JsonSerdeCodec;
use leptos::prelude::*;
use leptos_use::storage::use_local_storage;
use nostr::ToBech32;

use crate::modal::NostrAuthModal;
use crate::signers::AuthResult;
use crate::types::{NostrAuthConfig, PersistedSession};

#[cfg(not(feature = "ssr"))]
use wasm_bindgen_futures::spawn_local;

/// Reactive auth context — available anywhere inside [`NostrAuthProvider`].
///
/// Access via [`use_nostr_auth()`] or [`try_use_nostr_auth()`].
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct NostrAuthContext {
    /// Current auth result; `None` when not logged in.
    pub auth: Signal<Option<AuthResult>>,
    /// Convenience: the authenticated user's public key (bech32 npub and hex).
    pub public_key: Signal<Option<nostr::PublicKey>>,
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
    /// Log out: clears auth state and removes the localStorage session.
    pub logout: Callback<()>,
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
#[allow(clippy::exhaustive_structs)]
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
    // PersistedSession requires PartialEq (derived in lib.rs) for the equality check
    // that prevents spurious reactive updates.
    let (stored_session, set_stored_session, delete_stored_session) =
        use_local_storage::<Option<PersistedSession>, JsonSerdeCodec>(
            cfg.get_value().storage_key,
        );

    // Clone before Effect consumes delete_stored_session
    let delete_for_logout = delete_stored_session.clone();

    // stored_session and set_restoring are used only inside the non-ssr Effect block
    #[cfg(feature = "ssr")]
    let _ = (stored_session, set_restoring, delete_stored_session);

    // On mount: one-time session restore from localStorage.
    // get_untracked() avoids re-running this Effect when the session is saved
    // after a fresh login. Effects don't run on the server, so spawn_local is
    // safe to cfg-gate here.
    Effect::new(move |_| {
        #[cfg(not(feature = "ssr"))]
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
                        set_auth.set(Some(result));
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
    let is_restoring_signal = Signal::derive(move || restoring.get());

    let show_login = Callback::new(move |(): ()| set_show_modal.set(true));

    let logout = Callback::new(move |(): ()| {
        delete_for_logout(); // SSR-safe no-op on server
        set_auth.set(None);
    });

    provide_context(NostrAuthContext {
        auth: auth.into(),
        public_key,
        npub,
        is_authenticated,
        is_restoring: is_restoring_signal,
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
        set_auth.set(Some(result));
        set_show_modal.set(false);
    });

    let on_close_callback = Callback::new(move |(): ()| {
        set_show_modal.set(false);
    });

    view! {
        // Show a subtle loading indicator while restoring (optional — UX polish)
        <Show when=move || restoring.get() fallback=|| ()>
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
