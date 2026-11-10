#![expect(
    clippy::exhaustive_structs,
    reason = "#[component] generates the exported props struct, which cannot take attributes"
)]
use codee::string::JsonSerdeCodec;
use futures::future::{AbortHandle, Abortable};
use leptos::context::Provider;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_use_event_listener::use_event_listener;
use leptos_use_storage::{UseStorageError, UseStorageOptions, use_local_storage_with_options};
use leptos_use_window::use_window;
use nostr::nips::nip19::ToBech32;

use crate::modal::{Attempt, NostrAuthModal, ProviderLink};
use crate::platform::{effective_rp_id, page_has_been_active, prompt_allowed};
use crate::storage::{
    LoginStorageAction, RestorePlan, begin_passkey_restore, initial_restoring,
    is_logout_storage_event, login_storage_action, passkey_restore_target, restore_is_current,
    restore_plan, restore_session,
};
use crate::types::{AuthResult, NostrAuthConfig, NostrAuthError, PersistedSession};

/// Reactive auth context — available anywhere inside [`NostrAuthProvider`].
///
/// Access via [`use_nostr_auth()`] or [`try_use_nostr_auth()`].
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct NostrAuthContext {
    /// Current auth result; `None` when not logged in.
    ///
    /// `.get()` clones the session, including any in-memory key. `.with` avoids the copy.
    pub auth: Signal<Option<AuthResult>>,
    /// The authenticated user's public key.
    pub public_key: Signal<Option<nostr::key::PublicKey>>,
    /// The authenticated user's npub, or hex if bech32 encoding fails.
    pub npub: Signal<Option<String>>,
    /// `true` when a user is logged in. This is not proof of identity: a read-only session is a
    /// pasted npub, and a script on the page can read or change this, so a server must verify a
    /// signature instead.
    pub is_authenticated: Signal<bool>,
    /// `true` while a persisted session is being restored: from localStorage on mount, or for a
    /// passkey, from the login click.
    ///
    /// False on the first hydrated render, because server HTML cannot know storage, and false at
    /// load for a stored passkey, which restores only from the login click. It can stay true for
    /// minutes while a bunker relay is down, and an extension restore gives up after 30 s with
    /// `ExtensionTimeout`. Do not hide the login button behind it. A login, a logout or a logout in
    /// another tab ends it at once.
    pub is_restoring: Signal<bool>,
    /// `true` when localStorage holds a decodable session, restored or not, whether or not
    /// `persist_session` is on. Use it with `is_authenticated` to offer a "forget saved session"
    /// control that calls `logout`.
    ///
    /// False on the first hydrated render. After a login whose write failed, with nothing
    /// restorable stored, it reads true with nothing saved until logout, reload or a refetch from
    /// another tab's change.
    pub has_saved_session: Signal<bool>,
    /// Why the stored session did not restore. It is kept and retried on the next load, or for a
    /// passkey, on the next login click. `None` for a passkey awaiting that click, since nothing has
    /// failed; stored passkey data that can never restore is reported at load. Cleared by a login,
    /// a logout, a logout in another tab or a new attempt.
    ///
    /// Treat the text as untrusted display text: it can carry words from an extension or a relay.
    pub restore_error: Signal<Option<NostrAuthError>>,
    /// Open the login modal, or restore a stored passkey.
    ///
    /// Call `show_login` from a user gesture, such as a click handler, with nothing deferred before
    /// it, so that restoring a passkey takes one tap. Before the user's first interaction with the
    /// page, or in a browser that does not report user activation, it opens the login modal and
    /// never prompts. After that the crate does not check that the call is in a gesture: a call
    /// from a timer or Effect can prompt where the browser allows it. A failed or cancelled prompt
    /// keeps the session and opens the modal. While a prompt or restore is running, or when logged
    /// in, it only opens the modal.
    pub show_login: Callback<()>,
    /// Log out: clears auth state, removes the localStorage session and closes a bunker session
    /// for good, including for clones kept elsewhere. It also closes the login modal and cancels a
    /// login in it.
    pub logout: Callback<()>,
}

fn replace_auth(
    auth: ReadSignal<Option<AuthResult>>,
    set_auth: WriteSignal<Option<AuthResult>>,
    next: Option<AuthResult>,
) {
    // `with_untracked` would panic on a disposed signal, where `set` below does not.
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
/// Automatically attempts to restore a cached session from localStorage on mount, except a stored
/// passkey, which restores only from [`NostrAuthContext::show_login`] and never prompts on load.
/// Renders [`NostrAuthModal`] internally so you don't need to add it yourself.
///
/// # Session restore
///
/// A login is saved under [`NostrAuthConfig::storage_key`] unless it is an ncryptsec or raw nsec
/// login, and never with the user's Nostr secret key. A failed or cancelled prompt never clears the
/// stored session:
///
/// | Case | Stored session | Result |
/// |---|---|---|
/// | `logout`, logged in or not | Deleted | Logged out. An open modal closes, a login in it is cancelled and typed input is discarded |
/// | Stored passkey at page load | Kept | Logged out, no prompt. `restore_error` stays `None` unless the stored data can never restore. The login click restores it |
/// | Failed or cancelled restore, any method | Kept | Logged out, retried on the next load (once per load, never retried on a timer), or for a passkey on the next login click, whose failure also opens the modal |
/// | Another key on restore, any method | Kept | The other key is never adopted. `restore_error` is `SignerKeyMismatch`; switching the signer back restores it |
/// | Extension returns an invalid key string on restore | Kept | `restore_error` is `InvalidPublicKey`; restores once the extension returns the stored key |
/// | Extension does not answer within 30 s on restore | Kept | Logged out; `restore_error` is `ExtensionTimeout`. A later answer is discarded; retried on the next load |
/// | Stored data can never restore (bad hex, missing fields, bad base64) | Kept | Logged out, no prompt or network call; `restore_error` says why |
/// | Stored method not in `allowed_methods` | Kept | Logged out, no prompt or network call; `restore_error` is `RestoreMethodNotAllowed` |
/// | Stored JSON cannot be decoded | Kept | Reads as nothing stored. `logout` removes it |
/// | New login, persistable method | Overwritten | |
/// | New login, not persistable, same public key | Kept | A reload restores the stored login |
/// | New login, not persistable, different public key | Cleared | A reload is logged out instead of returning the old identity |
/// | New login whose write fails (quota), different public key | Cleared | The same |
/// | New login whose write fails, same public key | Kept | A reload restores the same identity |
/// | Login or logout during a restore | As above | The restore is cancelled, its result discarded, and `is_restoring` ends at once |
/// | Failed or cancelled login in the modal | Untouched | A restore in flight continues |
///
/// Per method, restore re-asks the extension for its key; opens a socket to the stored bunker relays
/// in order and sends `get_public_key` with the stored pairing key; or, for a passkey, runs
/// `navigator.credentials.get` from the login click. Each must return the stored key. A read-only
/// session restores from the stored key, which must be on the curve. A bunker's matching key does
/// not prove that the signer holds it, and a signer that answers `get_public_key` to a revoked
/// client restores as logged in, then fails at the first signature. Restore never resends the
/// bunker's one-time secret.
///
/// A bunker approval link during restore keeps `is_restoring` true while it waits. A cancelled
/// restore clears that link at once and closes its socket, and takes a passkey prompt down where
/// the browser honours it. An extension prompt stays until answered, and its result is discarded,
/// as it is after the 30 s restore deadline. A restore that lands while this provider's modal shows
/// its method list closes the modal. On a login step the modal stays open: closing it keeps the
/// restored session, and finishing the login replaces it like any new login.
///
/// # Other tabs
///
/// Any removal of the stored session logs out other tabs, through the browser's `storage` event,
/// and drops their in-memory keys, with no reason signal. A bunker session there closes for good.
/// Removals include another tab's `logout`, its login as a different identity with a method that
/// cannot persist, and its quota-failure clear. Limits:
///
/// - A removal cancels a login running in this tab's modal and closes the modal, with no reason
///   shown. A bunker login's one-time secret may be spent, so a retry can need a new URI. With no
///   login running the modal stays open with what was typed, and submitting it is a new login.
/// - A persistable login elsewhere leaves this tab logged in. A non-persistable login elsewhere logs
///   this tab out only when it replaces a stored session of another identity, even if this tab
///   holds the new login's identity.
/// - With nothing stored, removing it fires no `storage` event, so a logout in another tab does not
///   reach this one, which keeps its in-memory keys.
/// - `localStorage.clear()` in another tab logs this tab out whenever the browser fires a `storage`
///   event for it, even if nothing of ours was stored, because the event does not say what was
///   removed. An in-memory ncryptsec or nsec login ends too. Use `removeItem` for your own keys.
///   Chromium fires no event when the origin's storage was already empty.
/// - Undecodable bytes under our key count the same: removing them logs this tab out.
/// - A restore still running when another tab stores a different identity is dropped.
/// - A page restored from the back/forward cache gets no `storage` event for a logout that happened
///   meanwhile.
/// - `restore_error` can go stale if another tab logs in persistably while this tab stays logged
///   out.
/// - A persistable login in another tab during a held passkey prompt does not cancel the prompt.
///   Its result lands here while the other identity is stored.
///
/// # Example
/// ```rust,no_run
/// use leptos::prelude::*;
/// use leptos_nostr_auth::NostrAuthProvider;
///
/// #[component]
/// fn App() -> impl IntoView {
///     view! {
///         <NostrAuthProvider>
///             <p>"Your app"</p>
///         </NostrAuthProvider>
///     }
/// }
/// # fn main() {}
/// ```
#[expect(
    clippy::too_many_lines,
    reason = "one reactive setup; splitting it would only pass its signals around"
)]
#[component]
pub fn NostrAuthProvider(
    /// Optional configuration (default: [`NostrAuthConfig::default`]: every method but `RawNsec`,
    /// persistence on).
    #[prop(optional)]
    config: Option<NostrAuthConfig>,
    children: Children,
) -> impl IntoView {
    let config = config.unwrap_or_default();
    let cfg = StoredValue::new(config);

    let (auth, set_auth) = signal(None::<AuthResult>);
    let (show_modal, set_show_modal) = signal(false);
    let (write_failures, set_write_failures) = signal(0_u32);

    let (stored_session, set_stored_session, delete_stored_session) =
        use_local_storage_with_options::<Option<PersistedSession>, JsonSerdeCodec>(
            cfg.with_value(|c| c.storage_key.clone()),
            UseStorageOptions::default().on_error(move |e| {
                if matches!(e, UseStorageError::SetItemFailed(_)) {
                    set_write_failures.update(|n| *n = n.wrapping_add(1));
                }
            }),
        );

    let hydrating = Owner::current_shared_context().is_some_and(|sc| sc.during_hydration());
    let setup_plan = cfg.with_value(|c| {
        restore_plan(
            c.persist_session,
            stored_session.get_untracked().as_ref(),
            &c.allowed_methods,
        )
    });
    let (restoring, set_restoring) = signal(initial_restoring(hydrating, setup_plan));
    let (settled, set_settled) = signal(!hydrating);
    let (restore_error, set_restore_error) = signal(None::<NostrAuthError>);

    let attempt = Attempt::new();
    let restore_handle = StoredValue::new(None::<AbortHandle>);
    // The pubkey of a login whose failed write must delete what it could not replace.
    let clear_on_write_failure = StoredValue::new(None::<String>);

    on_cleanup(move || {
        restore_handle.with_value(|handle| {
            if let Some(handle) = handle {
                handle.abort();
            }
        });
    });

    let cancel_restore = move || {
        restore_handle.with_value(|handle| {
            if let Some(handle) = handle {
                handle.abort();
            }
        });
        set_restoring.set(false);
        set_restore_error.set(None);
        clear_on_write_failure.set_value(None);
    };

    let _ = use_event_listener(use_window(), leptos::ev::storage, move |ev| {
        let local = web_sys::window().and_then(|w| w.local_storage().ok().flatten());
        let is_local_area = local.is_some() && ev.storage_area() == local;
        let logged_out = cfg.with_value(|c| {
            is_logout_storage_event(
                c.persist_session,
                is_local_area,
                ev.key().as_deref(),
                ev.new_value().as_deref(),
                &c.storage_key,
            )
        });
        if logged_out {
            if attempt.cancel() {
                set_show_modal.set(false);
            }
            cancel_restore();
            replace_auth(auth, set_auth, None);
        }
    });

    // `immediate = false`: a load's own rewrite can fail before this subscribes, and must not count.
    Effect::watch(
        move || write_failures.get(),
        {
            let delete = delete_stored_session.clone();
            move |_, _, _| {
                let armed = clear_on_write_failure
                    .try_update_value(Option::take)
                    .flatten();
                if let Some(pubkey) = armed
                    && stored_session
                        .get_untracked()
                        .is_some_and(|s| s.public_key_hex == pubkey)
                {
                    delete();
                }
            }
        },
        false,
    );

    let land_restore = move |result: Result<AuthResult, NostrAuthError>| {
        match result {
            Ok(result) => {
                if restore_is_current(stored_session.get_untracked().as_ref(), &result) {
                    replace_auth(auth, set_auth, Some(result));
                } else {
                    result.close_session();
                }
                set_restore_error.set(None);
            }
            Err(e) => {
                web_sys::console::info_1(
                    &format!("leptos-nostr-auth: session restore failed: {e}").into(),
                );
                set_restore_error.set(Some(e));
            }
        }
        set_restoring.set(false);
    };

    // Reads storage afresh, because a logout during the consumer's first render runs before this.
    // get_untracked() avoids re-running when a login saves the session.
    Effect::new(move |_| {
        set_settled.set(true);
        let session = stored_session.get_untracked();
        let (plan, timeout) = cfg.with_value(|c| {
            (
                restore_plan(c.persist_session, session.as_ref(), &c.allowed_methods),
                c.bunker_timeout_secs,
            )
        });
        match (plan, session) {
            (RestorePlan::Restore, Some(session)) => {
                let (handle, registration) = AbortHandle::new_pair();
                restore_handle.set_value(Some(handle));
                set_restoring.set(true);
                spawn_local(async move {
                    if let Ok(result) =
                        Abortable::new(restore_session(&session, timeout), registration).await
                    {
                        land_restore(result);
                    }
                });
            }
            (RestorePlan::AwaitClick, Some(session)) => {
                if let Err(e) = passkey_restore_target(&session) {
                    set_restore_error.set(Some(e));
                }
            }
            (RestorePlan::NotAllowed, _) => {
                set_restore_error.set(Some(NostrAuthError::RestoreMethodNotAllowed));
            }
            _ => {}
        }
    });

    let public_key = Signal::derive(move || auth.with(|a| a.as_ref().map(AuthResult::public_key)));

    let npub = Signal::derive(move || {
        auth.with(|a| {
            a.as_ref().map(|a| {
                let pk = a.public_key();
                pk.to_bech32().unwrap_or_else(|_| pk.to_hex())
            })
        })
    });

    let is_authenticated = Signal::derive(move || auth.with(Option::is_some));

    let show_login = Callback::new(move |(): ()| {
        let may_prompt = !show_modal.get_untracked()
            && !restoring.get_untracked()
            && auth.with_untracked(Option::is_none)
            && prompt_allowed(page_has_been_active());
        let session = stored_session.get_untracked().filter(|session| {
            may_prompt
                && cfg.with_value(|c| {
                    restore_plan(c.persist_session, Some(session), &c.allowed_methods)
                }) == RestorePlan::AwaitClick
        });
        let Some(session) = session else {
            set_show_modal.set(true);
            return;
        };

        // `get` goes first: Safari counts it as user-initiated only inside the click's own stack.
        let begun = cfg
            .with_value(|c| begin_passkey_restore(&session, &effective_rp_id(c.rp_id.as_deref())));
        match begun {
            Ok(pending) => {
                let (handle, registration) = AbortHandle::new_pair();
                restore_handle.set_value(Some(handle));
                set_restore_error.set(None);
                set_restoring.set(true);
                spawn_local(async move {
                    if let Ok(result) = Abortable::new(pending.finish(), registration).await {
                        let failed = result.is_err();
                        land_restore(result);
                        if failed {
                            set_show_modal.set(true);
                        }
                    }
                });
            }
            Err(e) => {
                land_restore(Err(e));
                set_show_modal.set(true);
            }
        }
    });

    let has_saved_session =
        Signal::derive(move || settled.get() && stored_session.with(Option::is_some));

    let logout = Callback::new({
        let delete = delete_stored_session.clone();
        move |(): ()| {
            attempt.cancel();
            set_show_modal.set(false);
            cancel_restore();
            delete();
            replace_auth(auth, set_auth, None);
        }
    });

    provide_context(NostrAuthContext {
        auth: auth.into(),
        public_key,
        npub,
        is_authenticated,
        is_restoring: restoring.into(),
        has_saved_session,
        restore_error: restore_error.into(),
        show_login,
        logout,
    });

    let on_auth_callback = Callback::new(move |result: AuthResult| {
        cancel_restore();
        let action = login_storage_action(
            cfg.with_value(|c| c.persist_session),
            stored_session.get_untracked().as_ref(),
            &result.public_key(),
            result.to_persisted_session(),
        );
        match action {
            LoginStorageAction::Keep => {}
            LoginStorageAction::Overwrite {
                session,
                clear_on_failure,
            } => {
                if clear_on_failure {
                    clear_on_write_failure.set_value(Some(session.public_key_hex.clone()));
                }
                set_stored_session.set(Some(session));
            }
            LoginStorageAction::Clear => delete_stored_session(),
        }
        replace_auth(auth, set_auth, Some(result));
        set_show_modal.set(false);
    });

    let on_close_callback = Callback::new(move |(): ()| {
        set_show_modal.set(false);
    });

    let link = ProviderLink {
        attempt,
        is_authenticated,
    };

    view! {
        {children()}

        <Provider value=link>
            <NostrAuthModal
                open=Signal::from(show_modal)
                on_auth=on_auth_callback
                on_close=on_close_callback
                config=cfg.get_value()
            />
        </Provider>
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
    fn baseline_session_restores() {
        const BASELINE: &str = r#"{"public_key_hex":"82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2","method":"ReadOnly","bunker_uri":null,"bunker_client_secret_hex":null,"passkey_credential_id":null}"#;
        let dec = <JsonSerdeCodec as Decoder<Option<PersistedSession>>>::decode(BASELINE)
            .unwrap()
            .unwrap();
        assert_eq!(BASELINE, READ_ONLY_JSON);
        let restored = crate::storage::tests::first_poll(restore_session(&dec, 1));
        assert!(matches!(restored, Some(Ok(AuthResult::ReadOnly(_)))));
    }

    #[test]
    fn persisted_session_decodes_stored_literal() {
        let dec = |s| <JsonSerdeCodec as Decoder<Option<PersistedSession>>>::decode(s).unwrap();
        assert_eq!(dec(READ_ONLY_JSON), Some(read_only()));
        assert_eq!(dec(BUNKER_JSON), Some(bunker()));
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod stale_restore {
    use super::*;
    use crate::signers::test_ws::tick;
    use crate::types::PersistedMethod;
    use codee::Encoder as _;
    use wasm_bindgen::JsCast as _;
    use wasm_bindgen_test::wasm_bindgen_test;

    const USER: &str = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2";
    const OTHER: &str = "4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa";

    fn stored(pk: &str) -> String {
        JsonSerdeCodec::encode(&Some(PersistedSession {
            public_key_hex: pk.to_owned(),
            method: PersistedMethod::Extension,
            bunker_uri: None,
            bunker_client_secret_hex: None,
            passkey_credential_id: None,
        }))
        .unwrap()
    }

    #[component]
    fn Probe(out: StoredValue<Option<NostrAuthContext>>) -> impl IntoView {
        out.set_value(Some(use_nostr_auth()));
    }

    #[wasm_bindgen_test]
    async fn restore_landing_after_another_tab_stored_is_dropped() {
        crate::signers::test_ws::install();
        let key = NostrAuthConfig::default().storage_key;
        js_sys::eval(&format!(
            "globalThis.window = globalThis;
            const node = () => new Proxy(function () {{}}, {{
              get: (_, p) => (p === 'then' ? undefined : p === Symbol.toPrimitive ? () => '' : node()),
              set: () => true,
              apply: () => node(),
            }});
            globalThis.document = node();
            globalThis.__mountPoint = node();
            globalThis.Window = class {{ static [Symbol.hasInstance]() {{ return true; }} }};
            const bus = new EventTarget();
            globalThis.addEventListener = bus.addEventListener.bind(bus);
            globalThis.removeEventListener = bus.removeEventListener.bind(bus);
            globalThis.dispatchEvent = bus.dispatchEvent.bind(bus);
            const items = new Map([[{key:?}, {user:?}]]);
            Object.defineProperty(globalThis, 'localStorage', {{ configurable: true, value: {{
              getItem: (k) => items.has(k) ? items.get(k) : null,
              setItem: (k, v) => {{ items.set(k, String(v)); }},
              removeItem: (k) => {{ items.delete(k); }},
            }} }});
            globalThis.nostr = {{ getPublicKey: () => new Promise((r) => {{ globalThis.__answer = () => r({USER:?}); }}) }};",
            user = stored(USER),
        ))
        .unwrap();
        // Mounting nothing is the public way to start leptos's wasm executor.
        let mount_point = js_sys::eval("globalThis.__mountPoint").unwrap();
        leptos::mount::mount_to(mount_point.unchecked_into(), || ()).forget();

        let owner = Owner::new();
        let out = owner.with(|| StoredValue::new(None));
        let view =
            owner.with(|| view! { <NostrAuthProvider><Probe out=out /></NostrAuthProvider> });
        let ctx = out.get_value().unwrap();
        tick(20).await;
        assert!(ctx.is_restoring.get_untracked(), "restore did not start");

        js_sys::eval(&format!(
            "localStorage.setItem({key:?}, {other:?});
            const e = new Event('storage');
            Object.defineProperties(e, {{ key: {{ value: {key:?} }}, newValue: {{ value: {other:?} }}, storageArea: {{ value: localStorage }} }});
            dispatchEvent(e);",
            other = stored(OTHER),
        ))
        .unwrap();
        tick(20).await;
        js_sys::eval("globalThis.__answer()").unwrap();
        tick(20).await;

        let landed = ctx
            .auth
            .with_untracked(|a| a.as_ref().map(AuthResult::public_key));
        let settled = (
            ctx.is_restoring.get_untracked(),
            ctx.restore_error.get_untracked(),
        );
        js_sys::eval(
            "delete globalThis.nostr; delete globalThis.localStorage; delete globalThis.document;",
        )
        .unwrap();
        drop(view);
        drop(owner);
        assert_eq!(landed, None, "a stale restore logged this tab in");
        assert!(matches!(settled, (false, None)), "{settled:?}");
    }
}
