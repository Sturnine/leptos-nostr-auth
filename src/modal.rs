#![expect(
    clippy::exhaustive_structs,
    reason = "#[component] generates the props structs, which cannot take attributes"
)]
use futures::future::{AbortHandle, Abortable};
use leptos::portal::Portal;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_use_event_listener::use_event_listener;
use leptos_use_window::use_window;
use wasm_bindgen::JsCast as _;
use wasm_bindgen::prelude::{Closure, JsValue};
use zeroize::{Zeroize, Zeroizing};

use crate::platform::{Os, Platform, effective_rp_id, passkey_option_visible, prf_capability};
use crate::signers::{
    BunkerSession, Nip07Handle, PasskeySession, PendingPasskey, RawKeySession, ReadOnlyHandle,
    current_auth_url, dismiss_auth_prompt, register_auth_presenter, unregister_auth_presenter,
};
use crate::types::{AuthResult, LoginMethod, NostrAuthConfig, NostrAuthError};

#[derive(Clone, PartialEq)]
enum ModalStep {
    MethodSelect,
    Extension,
    Bunker,
    Passkey,
    ReadOnly,
    Ncryptsec,
    #[cfg(feature = "insecure_nsec_input")]
    RawNsecWarn,
    #[cfg(feature = "insecure_nsec_input")]
    RawNsec,
}

impl ModalStep {
    const fn title(&self) -> &'static str {
        match self {
            Self::MethodSelect => "Connect to Nostr",
            Self::Extension => "Browser Extension",
            Self::Bunker => "Nostr Connect",
            Self::Passkey => "Passkey",
            Self::ReadOnly => "Read-Only Access",
            Self::Ncryptsec => "Encrypted Key",
            #[cfg(feature = "insecure_nsec_input")]
            Self::RawNsecWarn | Self::RawNsec => "Secret Key",
        }
    }
}

#[derive(Clone, PartialEq)]
enum PasskeySubStep {
    Choose,
    Loading,
}

/// The login in flight. Dropping its future is what closes a bunker socket and clears its approval
/// link.
#[derive(Clone, Copy)]
pub(crate) struct Attempt(StoredValue<Option<AbortHandle>>);

impl Attempt {
    pub(crate) fn new() -> Self {
        Self(StoredValue::new(None))
    }

    /// Reports whether a login was running. A failed login counts as ended.
    pub(crate) fn cancel(self) -> bool {
        let handle = self.0.try_update_value(Option::take).flatten();
        handle.map(|handle| handle.abort()).is_some()
    }

    fn wrap(self, body: impl Future<Output = ()>) -> impl Future<Output = ()> {
        let (handle, registration) = AbortHandle::new_pair();
        let _ = self.0.try_set_value(Some(handle));
        async move {
            // An aborted body must not clear: `cancel` took its handle, and the stored one may be
            // a newer attempt's.
            if Abortable::new(body, registration).await.is_ok() {
                let _ = self.0.try_set_value(None);
            }
        }
    }

    fn spawn(self, body: impl Future<Output = ()> + 'static) {
        spawn_local(self.wrap(body));
    }
}

/// Links the provider to the modal it renders. A consumer's own modal never sees this.
#[derive(Clone, Copy)]
pub(crate) struct ProviderLink {
    /// The provider's modal's login in flight, cancelled synchronously on logout and removal.
    pub(crate) attempt: Attempt,
    pub(crate) is_authenticated: Signal<bool>,
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
enum EscapeAction {
    Close,
    DismissPrompt,
    Nothing,
}

const fn escape_action(open: bool, prompt_showing: bool) -> EscapeAction {
    match (open, prompt_showing) {
        (true, _) => EscapeAction::Close,
        (false, true) => EscapeAction::DismissPrompt,
        (false, false) => EscapeAction::Nothing,
    }
}

fn has_more_options(methods: &[LoginMethod]) -> bool {
    methods.iter().any(|method| match method {
        LoginMethod::ReadOnly | LoginMethod::Ncryptsec => true,
        #[cfg(feature = "insecure_nsec_input")]
        LoginMethod::RawNsec => true,
        LoginMethod::Extension | LoginMethod::Bunker | LoginMethod::Passkey => false,
    })
}

fn to_method_list(
    attempt: Attempt,
    set_step: WriteSignal<ModalStep>,
    set_error: WriteSignal<Option<String>>,
) {
    attempt.cancel();
    set_step.set(ModalStep::MethodSelect);
    set_error.set(None);
}

/// A text field's signal whose buffer is wiped when its owner is cleaned up. Handlers must not read
/// it with `.get()`, whose clone is freed unwiped. `prop:value` does, which is a documented limit.
fn secret_signal() -> (ReadSignal<String>, WriteSignal<String>) {
    let (read, write) = signal(String::new());
    on_cleanup(move || {
        let _ = write.try_update_untracked(Zeroize::zeroize);
    });
    (read, write)
}

/// `set` would free the previous buffer unwiped.
fn replace_secret(set: WriteSignal<String>, value: String) {
    set.update(|s| {
        s.zeroize();
        *s = value;
    });
}

/// Move the buffer out of a secret signal, with no copy, emptying the field. It is wiped on drop,
/// including when an aborted attempt drops its future.
fn take_secret(set: WriteSignal<String>) -> Zeroizing<String> {
    Zeroizing::new(set.try_update(core::mem::take).unwrap_or_default())
}

fn clear_secret(set: WriteSignal<String>) {
    drop(take_secret(set));
}

fn deliver(
    attempt: Attempt,
    set_step: WriteSignal<ModalStep>,
    set_error: WriteSignal<Option<String>>,
    on_auth: Callback<AuthResult>,
    result: AuthResult,
) {
    to_method_list(attempt, set_step, set_error);
    // `run` panics on a disposed callback. Dropping the value closes the session.
    let _ = on_auth.try_run(result);
}

/// The Nostr login modal widget.
///
/// Can be used standalone (you manage the `open` signal) or via [`NostrAuthProvider`].
///
/// # Example
/// ```rust,no_run
/// use leptos::prelude::*;
/// use leptos_nostr_auth::{AuthResult, NostrAuthModal};
///
/// #[component]
/// fn App() -> impl IntoView {
///     let (show, set_show) = signal(false);
///     view! {
///         <button on:click=move |_| set_show.set(true)>"Login"</button>
///         <NostrAuthModal
///             open=show
///             on_auth=move |result: AuthResult| {
///                 let _ = result.public_key();
///                 set_show.set(false);
///             }
///             on_close=move |()| set_show.set(false)
///         />
///     }
/// }
/// # fn main() {}
/// ```
///
/// # Typed secrets
///
/// The buffer of each input's signal is wiped with `zeroize` when a submit takes it, when a rejected
/// value is cleared and when the step is left. That is the signal's buffer and nothing else. The DOM
/// value, `event.target.value` and `prop:value` clones stay until the JS collector or the allocator
/// reuses them, and nothing here can reach copies inside `nostr`. Emptying a field does not undo
/// a paste, so a secret pasted in the wrong field should be treated as exposed.
///
/// The secret key and read-only inputs empty on every submit. The password input does too, except
/// on a submit refused for an empty ncryptsec field, which keeps it. A bunker URI stays after a
/// failed login, in clear text with any secret, until the user leaves the step, unless it is
/// [`NostrAuthError::InvalidBunkerUri`], which empties it. An ncryptsec string stays after
/// [`NostrAuthError::WrongPassword`] and empties on [`NostrAuthError::InvalidNcryptsec`].
#[expect(
    clippy::too_many_lines,
    reason = "one component body wires every login step"
)]
#[component]
pub fn NostrAuthModal(
    /// Reactive signal controlling modal visibility.
    #[prop(into)]
    open: Signal<bool>,
    /// Called with the `AuthResult` after successful login.
    #[prop(into)]
    on_auth: Callback<AuthResult>,
    /// Fired by the close button, backdrop click and Escape, not by a parent closing `open`.
    #[prop(optional, into)]
    on_close: Option<Callback<()>>,
    /// Library configuration.
    #[prop(optional)]
    config: Option<NostrAuthConfig>,
) -> impl IntoView {
    let config = StoredValue::new(config.unwrap_or_default());

    register_auth_presenter();
    on_cleanup(unregister_auth_presenter);

    // The server renders every method, and this Effect narrows the list after hydration.
    let (platform, set_platform) = signal(Platform::server_default());
    Effect::new(move |previous: Option<()>| {
        // Read first: `previous.is_none() || open.get()` would never subscribe on the first run.
        let is_open = open.get();
        if !is_open && previous.is_some() {
            return;
        }
        let detected = Platform::detect();
        // `&=`: setting it true here would flash a passkey button the check below then hides.
        set_platform.update(|platform| {
            platform.os = detected.os;
            platform.has_nostr_extension = detected.has_nostr_extension;
            platform.supports_webauthn &= detected.supports_webauthn;
        });
        spawn_local(async move {
            let visible =
                passkey_option_visible(detected.supports_webauthn, prf_capability().await);
            set_platform.update(|platform| platform.supports_webauthn = visible);
        });
    });

    let (step, set_step) = signal(ModalStep::MethodSelect);
    let (error, set_error) = signal(Option::<String>::None);

    let link = use_context::<ProviderLink>();
    let attempt = link.map_or_else(Attempt::new, |link| link.attempt);
    on_cleanup(move || {
        attempt.cancel();
    });

    let to_list = move || to_method_list(attempt, set_step, set_error);
    let back = Callback::new(move |(): ()| to_list());
    let on_auth = Callback::new(move |result: AuthResult| {
        deliver(attempt, set_step, set_error, on_auth, result);
    });

    let close = move || {
        to_list();
        if let Some(cb) = on_close {
            cb.run(());
        }
    };

    Effect::new(move |_| {
        if !open.get() {
            to_list();
        }
    });

    if let Some(link) = link {
        Effect::watch(
            move || link.is_authenticated.get(),
            // On a step the user chose a path and may have typed a secret, so a restore must not
            // take that away. The list implies no login is running. `authed` matters because a
            // removal in another tab sets auth to `None` under an idle modal.
            move |&authed, _, _| {
                if authed && step.get_untracked() == ModalStep::MethodSelect {
                    close();
                }
            },
            false,
        );
    }

    let _ = use_event_listener(use_window(), leptos::ev::keydown, {
        move |e| {
            if e.key() == "Escape" && config.get_value().close_on_escape {
                match escape_action(open.get_untracked(), untrack(current_auth_url).is_some()) {
                    EscapeAction::Close => close(),
                    EscapeAction::DismissPrompt => dismiss_auth_prompt(),
                    EscapeAction::Nothing => {}
                }
            }
        }
    });

    view! {
        <Portal>
            <Show when=move || open.get()>
                <div
                    data-nostr-backdrop=""
                    on:click={
                        move |_| {
                            if config.get_value().close_on_backdrop_click {
                                close();
                            }
                        }
                    }
                >
                    <div
                        role="dialog"
                        aria-modal="true"
                        aria-label="Connect to Nostr"
                        data-nostr-modal=""
                        on:click=|e| e.stop_propagation()
                    >
                        <ModalHeader
                            step=step
                            on_back=back
                            on_close=close
                        />

                        <div data-nostr-modal-body="">
                            {move || match step.get() {
                                ModalStep::MethodSelect => view! {
                                    <StepMethodSelect
                                        platform=platform
                                        config=config.get_value()
                                        set_step=set_step
                                    />
                                }.into_any(),
                                ModalStep::Extension => view! {
                                    <StepExtension
                                        attempt=attempt
                                        on_auth=on_auth
                                        set_error=set_error
                                        on_back=back
                                    />
                                }.into_any(),
                                ModalStep::Bunker => view! {
                                    <StepBunker
                                        attempt=attempt
                                        on_auth=on_auth
                                        set_error=set_error
                                        platform=platform
                                        config=config.get_value()
                                    />
                                }.into_any(),
                                ModalStep::Passkey => view! {
                                    <StepPasskey
                                        attempt=attempt
                                        on_auth=on_auth
                                        set_error=set_error
                                        config=config.get_value()
                                    />
                                }.into_any(),
                                ModalStep::ReadOnly => view! {
                                    <StepReadOnly
                                        on_auth=on_auth
                                        set_error=set_error
                                    />
                                }.into_any(),
                                ModalStep::Ncryptsec => view! {
                                    <StepNcryptsec
                                        attempt=attempt
                                        on_auth=on_auth
                                        set_error=set_error
                                    />
                                }.into_any(),
                                #[cfg(feature = "insecure_nsec_input")]
                                ModalStep::RawNsecWarn => view! {
                                    <StepRawNsecWarn set_step=set_step />
                                }.into_any(),
                                #[cfg(feature = "insecure_nsec_input")]
                                ModalStep::RawNsec => view! {
                                    <StepRawNsec on_auth=on_auth set_error=set_error />
                                }.into_any(),
                            }}
                        </div>

                        <AuthUrlPrompt />

                        <Show when=move || error.get().is_some()>
                            <div
                                role="alert"
                                data-nostr-error=""
                            >
                                {move || error.get().unwrap_or_default()}
                            </div>
                        </Show>
                    </div>
                </div>
            </Show>
            // Challenges often arrive at signing and at restore, with the modal closed
            <Show when=move || !open.get() && current_auth_url().is_some()>
                <div
                    data-nostr-backdrop=""
                    on:click=move |_| {
                        if config.get_value().close_on_backdrop_click {
                            dismiss_auth_prompt();
                        }
                    }
                >
                    <div
                        role="dialog"
                        aria-modal="true"
                        aria-label="Approve a pending request"
                        data-nostr-modal=""
                        on:click=|e| e.stop_propagation()
                    >
                        <AuthUrlPrompt />
                        <button
                            aria-label="Dismiss approval link"
                            data-nostr-close=""
                            on:click=move |_| dismiss_auth_prompt()
                        >
                            "Dismiss"
                        </button>
                    </div>
                </div>
            </Show>
        </Portal>
    }
}

/// The signer's approval link. A click link, never a popup, with the full URL as its text, because
/// a hostile signer can send a phishing link.
#[component]
fn AuthUrlPrompt() -> impl IntoView {
    view! {
        {move || current_auth_url().map(|url| {
            let href = url.clone();
            view! {
                <div data-nostr-auth-prompt="">
                    <p>"Your remote signer asks you to approve a pending request"</p>
                    <a
                        href=href
                        target="_blank"
                        rel="noopener noreferrer"
                        data-nostr-auth-url=""
                    >
                        {url}
                    </a>
                </div>
            }
        })}
    }
}

#[component]
fn ModalHeader(
    step: ReadSignal<ModalStep>,
    on_back: Callback<()>,
    on_close: impl Fn() + 'static,
) -> impl IntoView {
    let show_back = move || step.get() != ModalStep::MethodSelect;

    view! {
        <div
            data-nostr-modal-header=""
        >
            <div>
                <Show when=show_back>
                    <button
                        aria-label="Back to login methods"
                        data-nostr-back=""
                        on:click=move |_| on_back.run(())
                    >
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M19 12H5M12 5l-7 7 7 7"/>
                        </svg>
                    </button>
                </Show>
                <h2
                    data-nostr-modal-title=""
                >
                    {move || step.get().title()}
                </h2>
            </div>
            <button
                aria-label="Close login modal"
                data-nostr-close=""
                on:click=move |_| on_close()
            >
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M18 6L6 18M6 6l12 12"/>
                </svg>
            </button>
        </div>
    }
}

#[component]
fn StepMethodSelect(
    platform: ReadSignal<Platform>,
    config: NostrAuthConfig,
    set_step: WriteSignal<ModalStep>,
) -> impl IntoView {
    let methods = config.allowed_methods;
    let has = |m: &LoginMethod| methods.contains(m);

    let passkey_allowed = has(&LoginMethod::Passkey);
    let extension_allowed = has(&LoginMethod::Extension);
    let show_bunker = has(&LoginMethod::Bunker);
    let show_readonly = has(&LoginMethod::ReadOnly);
    let show_ncryptsec = has(&LoginMethod::Ncryptsec);
    let show_more = has_more_options(&methods);
    #[cfg(feature = "insecure_nsec_input")]
    let advanced = has(&LoginMethod::RawNsec).then(|| {
        view! {
            <details data-nostr-advanced="">
                <summary>
                    "Advanced"
                </summary>
                <div>
                    <MethodButton
                        icon=icon_warning
                        title="Secret Key"
                        subtitle="⚠️ Paste nsec — not recommended for web use"
                        on_click=move || set_step.set(ModalStep::RawNsecWarn)
                    />
                </div>
            </details>
        }
    });
    #[cfg(not(feature = "insecure_nsec_input"))]
    let advanced = ();

    let show_passkey = move || platform.get().supports_webauthn && passkey_allowed;

    view! {
        <div data-nostr-methods="">

            <Show when=move || matches!(platform.get().os, Os::Apple) && show_passkey()>
                <MethodButton
                    icon=icon_passkey
                    title="Passkey"
                    subtitle="Face ID, Touch ID or a security key"
                    badge=Some("Recommended")
                    on_click=move || set_step.set(ModalStep::Passkey)
                />
            </Show>

            <Show when=move || platform.get().has_nostr_extension && extension_allowed>
                <MethodButton
                    icon=icon_extension
                    title="Browser Extension"
                    subtitle="Alby, nos2x, Nostr KeyX, and more"
                    badge=Signal::derive(move || {
                        (!matches!(platform.get().os, Os::Apple)).then_some("Recommended")
                    })
                    on_click=move || set_step.set(ModalStep::Extension)
                />
            </Show>

            <Show when=move || show_bunker>
                <MethodButton
                    icon=icon_bunker
                    title="Nostr Connect"
                    subtitle="Paste a bunker:// URI from nsecBunker or Amber"
                    on_click=move || set_step.set(ModalStep::Bunker)
                />
            </Show>

            <Show when=move || !matches!(platform.get().os, Os::Apple) && show_passkey()>
                <MethodButton
                    icon=icon_passkey
                    title="Passkey"
                    subtitle="Windows Hello · Android biometric"
                    on_click=move || set_step.set(ModalStep::Passkey)
                />
            </Show>

            <Show when=move || show_more>
                <div data-nostr-divider="">
                    "More options"
                </div>
            </Show>

            <Show when=move || show_ncryptsec>
                <MethodButton
                    icon=icon_ncryptsec
                    title="Encrypted Key"
                    subtitle="Decrypt an ncryptsec1... key with your password"
                    on_click=move || set_step.set(ModalStep::Ncryptsec)
                />
            </Show>

            <Show when=move || show_readonly>
                <MethodButton
                    icon=icon_read_only
                    title="Read-Only"
                    subtitle="Paste an npub — browse without posting"
                    on_click=move || set_step.set(ModalStep::ReadOnly)
                />
            </Show>

            {advanced}
        </div>
    }
}

#[component]
fn MethodButton(
    icon: impl IntoView + 'static,
    title: &'static str,
    subtitle: &'static str,
    #[prop(optional, into)] badge: MaybeProp<&'static str>,
    on_click: impl Fn() + 'static,
) -> impl IntoView {
    view! {
        <button
            data-nostr-method=""
            aria-label=format!("Login with {title}")
            on:click=move |_| on_click()
        >
            <span data-nostr-method-icon="">
                {icon}
            </span>
            <span>
                <span
                    data-nostr-method-title=""
                >
                    {title}
                    {move || badge.get().map(|b| view! {
                        <span
                            data-nostr-badge=""
                        >
                            {b}
                        </span>
                    })}
                </span>
                <span
                    data-nostr-method-subtitle=""
                >
                    {subtitle}
                </span>
            </span>
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 18l6-6-6-6"/>
            </svg>
        </button>
    }
}

fn icon_extension() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18"/></svg> }
}
fn icon_passkey() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> }
}
fn icon_bunker() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M12 2a4 4 0 0 1 4 4v5H8V6a4 4 0 0 1 4-4z"/><circle cx="12" cy="16" r="1" fill="currentColor"/></svg> }
}
fn icon_read_only() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> }
}
fn icon_ncryptsec() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> }
}
#[cfg(feature = "insecure_nsec_input")]
fn icon_warning() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg> }
}

#[component]
fn StepExtension(
    attempt: Attempt,
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
    on_back: Callback<()>,
) -> impl IntoView {
    let (loading, set_loading) = signal(true);

    let login = move || {
        set_error.set(None);
        set_loading.set(true);
        attempt.spawn(async move {
            match Nip07Handle::get_public_key().await {
                Ok(handle) => {
                    set_loading.set(false);
                    on_auth.run(AuthResult::Extension(handle));
                }
                Err(e) => {
                    set_error.set(Some(e.to_string()));
                    set_loading.set(false);
                }
            }
        });
    };

    Effect::new(move |_| login());

    view! {
        <div data-nostr-step="extension">
            <Show when=move || loading.get()>
                <span
                    aria-label="Waiting for extension…"
                    aria-live="polite"
                    data-nostr-spinner=""
                />
                <p>
                    "Waiting for extension approval…"
                </p>
            </Show>
            <Show when=move || !loading.get()>
                <button
                    on:click=move |_| login()
                >
                    "Try again"
                </button>
                <button
                    on:click=move |_| on_back.run(())
                >
                    "Choose a different method"
                </button>
            </Show>
        </div>
    }
}

#[component]
fn StepBunker(
    attempt: Attempt,
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
    platform: ReadSignal<Platform>,
    config: NostrAuthConfig,
) -> impl IntoView {
    let (uri, set_uri) = secret_signal();
    let (loading, set_loading) = signal(false);
    let timeout = config.bunker_timeout_secs;

    let connect = move || {
        if loading.get_untracked() {
            return;
        }
        let uri_val = uri.with_untracked(|u| Zeroizing::new(u.trim().to_owned()));
        if uri_val.is_empty() {
            set_error.set(Some("Please paste a bunker:// URI.".into()));
            return;
        }
        set_error.set(None);
        set_loading.set(true);
        attempt.spawn(async move {
            match BunkerSession::connect(&uri_val, timeout).await {
                Ok(session) => {
                    set_loading.set(false);
                    on_auth.run(AuthResult::Bunker(Box::new(session)));
                }
                Err(e) => {
                    // Nothing was sent and a retry cannot succeed, and this may be a pasted nsec.
                    if matches!(e, NostrAuthError::InvalidBunkerUri(_)) {
                        clear_secret(set_uri);
                    }
                    set_error.set(Some(e.to_string()));
                    set_loading.set(false);
                }
            }
        });
    };

    view! {
        <div data-nostr-step="bunker">
            <p>
                "Paste a "
                <code>
                    "bunker://"
                </code>
                " URI from nsecBunker, Amber, or any NIP-46 signer."
            </p>

            <div
                data-nostr-tip=""
            >
                "A bunker URI can hold a one-time secret, so keep it off shared screens. If a retry fails, the secret may be used up: get a new URI from your signer."
            </div>

            <Show when=move || matches!(platform.get().os, Os::Android)>
                <div
                    data-nostr-tip=""
                >
                    "Using Amber? Open Amber → Settings → Enable NIP-46 Bunker → copy the URI here."
                </div>
            </Show>

            <input
                type="text"
                placeholder="bunker://..."
                autocomplete="off"
                spellcheck="false"
                data-nostr-input="bunker-uri"
                aria-label="Bunker URI"
                on:input=move |e| replace_secret(set_uri, event_target_value(&e))
                prop:value=move || uri.get()
                on:keydown={
                    move |e: web_sys::KeyboardEvent| {
                        if e.key() == "Enter" { connect(); }
                    }
                }
            />

            <button
                disabled=move || loading.get()
                on:click=move |_| connect()
            >
                <Show when=move || loading.get() fallback=|| view! { "Connect" }>
                    <span data-nostr-spinner="" />
                    "Connecting…"
                </Show>
            </button>
        </div>
    }
}

#[component]
fn StepPasskey(
    attempt: Attempt,
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
    config: NostrAuthConfig,
) -> impl IntoView {
    let (sub_step, set_sub_step) = signal(PasskeySubStep::Choose);
    let rp_id = StoredValue::new(config.rp_id);
    let rp_name = StoredValue::new(config.rp_name);

    let (orphan, set_orphan) = signal(false);

    let await_ceremony =
        move |begun: Result<PendingPasskey, NostrAuthError>, creating: bool| match begun {
            Ok(pending) => {
                set_sub_step.set(PasskeySubStep::Loading);
                set_error.set(None);
                set_orphan.set(false);
                attempt.spawn(async move {
                    match pending.finish().await {
                        Ok(session) => on_auth.run(AuthResult::Passkey(session)),
                        Err(e) => {
                            set_orphan
                                .set(creating && matches!(e, NostrAuthError::PasskeyNotSupported));
                            set_error.set(Some(e.to_string()));
                            set_sub_step.set(PasskeySubStep::Choose);
                        }
                    }
                });
            }
            Err(e) => set_error.set(Some(e.to_string())),
        };

    view! {
        <div data-nostr-step="passkey">
            <Show when=move || orphan.get()>
                <div data-nostr-info="">
                    "A passkey may have been saved anyway. Remove the 'nostr' passkey from your password manager or device before trying again."
                </div>
            </Show>
            <Show when=move || sub_step.get() == PasskeySubStep::Choose fallback=move || view! {
                <div>
                    <span
                        aria-label="Waiting for biometric…"
                        aria-live="polite"
                        data-nostr-spinner=""
                    />
                    <p>
                        "Complete the biometric prompt…"
                    </p>
                </div>
            }>
                <p>
                    "Your Nostr identity is derived from your passkey using a deterministic algorithm.
                    A synced passkey gives the same Nostr key on your devices wherever this library runs with the same RP ID."
                </p>

                <button
                    on:click=move |_| {
                        let rp = rp_id.with_value(|rp_id| effective_rp_id(rp_id.as_deref()));
                        let begun = rp_name
                            .with_value(|rp_name| PasskeySession::begin_create(&rp, rp_name));
                        await_ceremony(begun, true);
                    }
                >
                    "Create new Nostr identity"
                </button>

                <button
                    on:click=move |_| {
                        let rp = rp_id.with_value(|rp_id| effective_rp_id(rp_id.as_deref()));
                        // `None`: a discoverable login, where the browser offers every stored passkey.
                        await_ceremony(PasskeySession::begin_authenticate(&rp, None), false);
                    }
                >
                    "I already have a Nostr passkey — restore it"
                </button>
            </Show>
        </div>
    }
}

#[component]
fn StepReadOnly(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (input, set_input) = secret_signal();

    let submit = move || {
        let val = take_secret(set_input);
        match val.parse::<ReadOnlyHandle>() {
            Ok(handle) => on_auth.run(AuthResult::ReadOnly(handle)),
            Err(e) => set_error.set(Some(e.to_string())),
        }
    };

    view! {
        <div data-nostr-step="readonly">
            <div
                data-nostr-info=""
            >
                "Read-only mode — you can browse but cannot post or send messages."
            </div>

            <div
                data-nostr-warning=""
            >
                "Never paste a secret key here. Only a public key belongs in this field. About half of all 64-character hex secret keys are also valid public keys, so a mistake cannot always be detected. Anything rejected is cleared from this field."
            </div>

            <input
                type="text"
                placeholder="npub1... or nprofile1... or 64-char hex"
                autocomplete="off"
                spellcheck="false"
                data-nostr-input="pubkey"
                aria-label="Public key (npub, nprofile, or hex)"
                on:input=move |e| replace_secret(set_input, event_target_value(&e))
                prop:value=move || input.get()
                on:keydown=move |e: web_sys::KeyboardEvent| {
                    if e.key() == "Enter" { submit(); }
                }
            />

            <button
                on:click=move |_| submit()
            >
                "Browse read-only"
            </button>
        </div>
    }
}

/// Give the browser a chance to paint before scrypt blocks the thread: two frames, or a 200 ms timer
/// that browsers may throttle in a background tab. Best effort, no paint is guaranteed. A frame
/// slower than the timer also starts scrypt before the paint.
async fn yield_for_paint() {
    // rAF never fires in a hidden tab, so a backgrounded login would otherwise stall until refocus.
    const PAINT_WAIT_MS: i32 = 200;
    let Some(window) = web_sys::window() else {
        return;
    };
    let promise = js_sys::Promise::new(&mut |resolve, _| {
        let second_frame = {
            let resolve = resolve.clone();
            Closure::once_into_js(move || {
                let _ = resolve.call0(&JsValue::UNDEFINED);
            })
        };
        let first_frame = {
            let window = window.clone();
            Closure::once_into_js(move || {
                let _ = window.request_animation_frame(second_frame.unchecked_ref());
            })
        };
        let _ = window.request_animation_frame(first_frame.unchecked_ref());
        let _ =
            window.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, PAINT_WAIT_MS);
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

#[component]
fn StepNcryptsec(
    attempt: Attempt,
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (ncryptsec, set_ncryptsec) = secret_signal();
    let (password, set_password) = secret_signal();
    let (loading, set_loading) = signal(false);

    let decrypt = move || {
        if loading.get_untracked() {
            return;
        }
        let nc = ncryptsec.with_untracked(|v| Zeroizing::new(v.trim().to_owned()));
        if nc.is_empty() {
            set_error.set(Some("Please paste your ncryptsec1... key.".into()));
            return;
        }
        if password.with_untracked(String::is_empty) {
            set_error.set(Some("Please enter your password.".into()));
            return;
        }
        let pw = take_secret(set_password);
        set_error.set(None);
        set_loading.set(true);
        attempt.spawn(async move {
            yield_for_paint().await;
            match RawKeySession::from_ncryptsec(&nc, &pw) {
                Ok(session) => {
                    set_loading.set(false);
                    on_auth.run(AuthResult::Ncryptsec(session));
                }
                Err(e) => {
                    // No password can open this value, and until it parses it may be a pasted nsec.
                    if matches!(e, NostrAuthError::InvalidNcryptsec(_)) {
                        clear_secret(set_ncryptsec);
                    }
                    set_error.set(Some(e.to_string()));
                    set_loading.set(false);
                }
            }
        });
    };

    view! {
        <div data-nostr-step="ncryptsec">
            <p>
                "Paste your "
                <code>
                    "ncryptsec1..."
                </code>
                " encrypted key and enter your password to decrypt it. A value no password can open is cleared from this field."
            </p>

            <input
                type="text"
                placeholder="ncryptsec1..."
                autocomplete="off"
                spellcheck="false"
                data-nostr-input="ncryptsec"
                aria-label="ncryptsec encrypted key"
                on:input=move |e| replace_secret(set_ncryptsec, event_target_value(&e))
                prop:value=move || ncryptsec.get()
            />

            <input
                type="password"
                placeholder="Password"
                autocomplete="off"
                spellcheck="false"
                data-nostr-input="ncryptsec-password"
                aria-label="ncryptsec decryption password"
                on:input=move |e| replace_secret(set_password, event_target_value(&e))
                prop:value=move || password.get()
                on:keydown=move |e: web_sys::KeyboardEvent| {
                    if e.key() == "Enter" { decrypt(); }
                }
            />

            <button
                disabled=move || loading.get()
                on:click=move |_| decrypt()
            >
                <Show when=move || loading.get() fallback=|| view! { "Decrypt and sign in" }>
                    <span data-nostr-spinner="" />
                    "Decrypting…"
                </Show>
            </button>
        </div>
    }
}

#[cfg(feature = "insecure_nsec_input")]
#[component]
fn StepRawNsecWarn(set_step: WriteSignal<ModalStep>) -> impl IntoView {
    view! {
        <div data-nostr-step="nsec-warn">
            <div
                role="alert"
                data-nostr-warning=""
            >
                <p>
                    "⚠️ This is not recommended"
                </p>
                <ul>
                    <li>"Any malicious script on this page can steal your key"</li>
                    <li>"Your clipboard may be monitored"</li>
                    <li>"Use a browser extension or passkey instead"</li>
                </ul>
            </div>
            <p>
                "If you understand the risks and still want to proceed, tap below."
            </p>
            <button
                on:click=move |_| set_step.set(ModalStep::RawNsec)
            >
                "I understand the risks — continue"
            </button>
        </div>
    }
}

#[cfg(feature = "insecure_nsec_input")]
#[component]
fn StepRawNsec(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (nsec, set_nsec) = secret_signal();

    let import = move || {
        let val = take_secret(set_nsec);
        match RawKeySession::from_nsec_or_hex(&val) {
            Ok(session) => on_auth.run(AuthResult::RawNsec(session)),
            Err(e) => set_error.set(Some(e.to_string())),
        }
    };

    view! {
        <div data-nostr-step="nsec">
            <input
                type="password"
                autocomplete="off"
                spellcheck="false"
                placeholder="nsec1... or 64-char hex"
                data-nostr-input="nsec"
                aria-label="Secret key (nsec or hex)"
                on:input=move |e| replace_secret(set_nsec, event_target_value(&e))
                prop:value=move || nsec.get()
                on:keydown=move |e: web_sys::KeyboardEvent| {
                    if e.key() == "Enter" { import(); }
                }
            />
            <button
                on:click=move |_| import()
            >
                "Import secret key"
            </button>
        </div>
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod tests {
    use super::*;
    use crate::storage::tests::first_poll;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    const USER: &str = "82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2";

    fn read_only() -> AuthResult {
        AuthResult::ReadOnly(USER.parse().unwrap())
    }

    #[test]
    fn attempt_cancel_before_poll_skips_body() {
        let attempt = Attempt::new();
        let ran = Arc::new(AtomicBool::new(false));
        let captured = Arc::new(());
        let (flag, held) = (Arc::clone(&ran), Arc::clone(&captured));
        let wrapped = attempt.wrap(async move {
            drop(held);
            flag.store(true, Ordering::SeqCst);
        });
        assert!(attempt.cancel());
        assert_eq!(first_poll(wrapped), Some(()));
        assert!(!ran.load(Ordering::SeqCst));
        assert_eq!(Arc::strong_count(&captured), 1);
    }

    #[test]
    fn attempt_runs_uncancelled_body() {
        let attempt = Attempt::new();
        let ran = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&ran);
        let wrapped = attempt.wrap(async move { flag.store(true, Ordering::SeqCst) });
        assert_eq!(first_poll(wrapped), Some(()));
        assert!(ran.load(Ordering::SeqCst));
    }

    #[test]
    fn attempt_cancel_reports_running() {
        let attempt = Attempt::new();
        assert!(!attempt.cancel());
        let unfinished = attempt.wrap(core::future::ready(()));
        assert!(attempt.cancel());
        assert!(!attempt.cancel());
        drop(unfinished);
        let finished = attempt.wrap(core::future::ready(()));
        assert_eq!(first_poll(finished), Some(()));
        assert!(!attempt.cancel());
    }

    #[test]
    fn attempt_cancel_keeps_newer_handle() {
        let attempt = Attempt::new();
        let older = attempt.wrap(core::future::ready(()));
        assert!(attempt.cancel());
        let newer = attempt.wrap(core::future::ready(()));
        assert_eq!(first_poll(older), Some(()));
        assert!(attempt.cancel());
        drop(newer);
    }

    #[test]
    fn deliver_resets_then_forwards() {
        let owner = Owner::new();
        owner.with(|| {
            let (step, set_step) = signal(ModalStep::Bunker);
            let (error, set_error) = signal(Some("old".to_owned()));
            let calls = Arc::new(AtomicUsize::new(0));
            let counter = Arc::clone(&calls);
            let on_auth = Callback::new(move |result: AuthResult| {
                assert_eq!(result.public_key().to_hex(), USER);
                counter.fetch_add(1, Ordering::SeqCst);
            });
            let attempt = Attempt::new();
            let running = attempt.wrap(core::future::ready(()));
            deliver(attempt, set_step, set_error, on_auth, read_only());
            assert!(step.get_untracked() == ModalStep::MethodSelect);
            assert_eq!(error.get_untracked(), None);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert!(!attempt.cancel());
            drop(running);
        });
    }

    #[test]
    fn escape_action_table() {
        assert_eq!(escape_action(true, false), EscapeAction::Close);
        assert_eq!(escape_action(true, true), EscapeAction::Close);
        assert_eq!(escape_action(false, true), EscapeAction::DismissPrompt);
        assert_eq!(escape_action(false, false), EscapeAction::Nothing);
    }

    #[test]
    fn has_more_options_table() {
        use LoginMethod::{Bunker, Extension, Ncryptsec, Passkey, ReadOnly};
        assert!(!has_more_options(&[]));
        assert!(!has_more_options(&[Extension, Bunker, Passkey]));
        assert!(has_more_options(&[Extension, ReadOnly]));
        assert!(has_more_options(&[Ncryptsec]));
    }

    #[cfg(feature = "insecure_nsec_input")]
    #[test]
    fn has_more_options_raw_nsec() {
        assert!(has_more_options(&[LoginMethod::RawNsec]));
    }

    #[cfg(all(feature = "ssr", feature = "insecure_nsec_input"))]
    #[test]
    fn raw_nsec_needs_listing_in_allowed_methods() {
        assert!(!LoginMethod::all().contains(&LoginMethod::RawNsec));
        let owner = Owner::new();
        let html = owner.with(|| {
            let (platform, _) = signal(Platform {
                os: Os::Other,
                has_nostr_extension: false,
                supports_webauthn: true,
            });
            let (_, set_step) = signal(ModalStep::MethodSelect);
            view! { <StepMethodSelect platform=platform config=NostrAuthConfig::default() set_step=set_step /> }
                .to_html()
        });
        assert!(!html.contains("Secret Key"), "{html}");
        let mut listed = LoginMethod::all();
        listed.push(LoginMethod::RawNsec);
        assert!(method_list_html(Os::Other, listed).contains("Secret Key"));
    }

    #[cfg(feature = "ssr")]
    fn method_list_html(os: Os, allowed_methods: Vec<LoginMethod>) -> String {
        let owner = Owner::new();
        owner.with(|| {
            let (platform, _) = signal(Platform {
                os,
                has_nostr_extension: false,
                supports_webauthn: true,
            });
            let (_, set_step) = signal(ModalStep::MethodSelect);
            let config = NostrAuthConfig {
                allowed_methods,
                ..NostrAuthConfig::default()
            };
            view! { <StepMethodSelect platform=platform config=config set_step=set_step /> }
                .to_html()
        })
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn method_list_divider_html() {
        use LoginMethod::{Bunker, ReadOnly};
        assert!(!method_list_html(Os::Other, vec![Bunker]).contains("data-nostr-divider"));
        assert!(method_list_html(Os::Other, vec![Bunker, ReadOnly]).contains("data-nostr-divider"));
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn method_list_no_amber_on_android() {
        let html = method_list_html(Os::Android, vec![LoginMethod::Bunker]);
        assert!(!html.contains("Login with Amber"));
        assert_eq!(html.matches("Login with Nostr Connect").count(), 1);
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn method_list_apple_subtitle() {
        let html = method_list_html(Os::Apple, vec![LoginMethod::Passkey]);
        assert!(html.contains("Face ID"));
        assert!(!html.contains("iCloud"));
    }

    #[cfg(feature = "ssr")]
    fn in_owner(
        view: impl FnOnce(WriteSignal<Option<String>>, Callback<AuthResult>) -> String,
    ) -> String {
        let owner = Owner::new();
        owner.with(|| {
            let (_, set_error) = signal(None::<String>);
            view(set_error, Callback::new(|_: AuthResult| {}))
        })
    }

    #[cfg(feature = "ssr")]
    fn bunker_html() -> String {
        in_owner(|set_error, on_auth| {
            let (platform, _) = signal(Platform {
                os: Os::Other,
                has_nostr_extension: false,
                supports_webauthn: true,
            });
            view! {
                <StepBunker
                    attempt=Attempt::new()
                    on_auth=on_auth
                    set_error=set_error
                    platform=platform
                    config=NostrAuthConfig::default()
                />
            }
            .to_html()
        })
    }

    #[cfg(feature = "ssr")]
    fn ncryptsec_html() -> String {
        in_owner(|set_error, on_auth| {
            view! { <StepNcryptsec attempt=Attempt::new() on_auth=on_auth set_error=set_error /> }
                .to_html()
        })
    }

    #[cfg(feature = "ssr")]
    fn read_only_html() -> String {
        in_owner(|set_error, on_auth| {
            view! { <StepReadOnly on_auth=on_auth set_error=set_error /> }.to_html()
        })
    }

    #[cfg(feature = "ssr")]
    fn assert_inputs_opt_out(html: &str, inputs: usize) {
        let tags: Vec<&str> = html
            .split("<input")
            .skip(1)
            .filter_map(|rest| rest.split('>').next())
            .collect();
        assert_eq!(tags.len(), inputs, "{html}");
        for tag in tags {
            assert!(tag.contains(r#"autocomplete="off""#), "{tag}");
            assert!(tag.contains(r#"spellcheck="false""#), "{tag}");
        }
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn secret_inputs_opt_out_of_autofill() {
        assert_inputs_opt_out(&bunker_html(), 1);
        assert_inputs_opt_out(&ncryptsec_html(), 2);
        assert_inputs_opt_out(&read_only_html(), 1);
    }

    #[cfg(all(feature = "ssr", feature = "insecure_nsec_input"))]
    #[test]
    fn nsec_input_opts_out_of_autofill() {
        let html = in_owner(|set_error, on_auth| {
            view! { <StepRawNsec on_auth=on_auth set_error=set_error /> }.to_html()
        });
        assert_inputs_opt_out(&html, 1);
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn readonly_step_warns_against_secret_keys() {
        let html = read_only_html();
        assert!(html.contains("data-nostr-warning"), "{html}");
        assert!(
            html.contains(
                "Never paste a secret key here. Only a public key belongs in this field. About half of all 64-character hex secret keys are also valid public keys, so a mistake cannot always be detected. "
            ),
            "{html}"
        );
        assert!(
            html.contains("Anything rejected is cleared from this field."),
            "{html}"
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn bunker_step_warns_about_one_time_secret() {
        let html = bunker_html();
        assert!(html.contains("data-nostr-tip"), "{html}");
        assert!(
            html.contains(
                "A bunker URI can hold a one-time secret, so keep it off shared screens. If a retry fails, the secret may be used up: get a new URI from your signer."
            ),
            "{html}"
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn ncryptsec_step_says_rejected_values_clear() {
        let html = ncryptsec_html();
        assert!(
            html.contains("A value no password can open is cleared from this field."),
            "{html}"
        );
    }

    #[test]
    fn deliver_survives_disposed_callback() {
        let owner = Owner::new();
        owner.with(|| {
            let (_, set_step) = signal(ModalStep::Bunker);
            let (_, set_error) = signal(None::<String>);
            let callback_owner = Owner::new();
            let on_auth = callback_owner.with(|| Callback::new(|_: AuthResult| {}));
            callback_owner.cleanup();
            deliver(Attempt::new(), set_step, set_error, on_auth, read_only());
        });
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;
    use crate::signers::memory_probe::{matches, sentinel};
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn take_secret_wipes_buffer_on_drop() {
        let (read, set) = signal(String::new());
        let value = sentinel();
        let expected = value.clone().into_bytes();
        let addr = value.as_ptr().addr();
        set.set(value);
        assert_eq!(read.with_untracked(|s| s.as_ptr().addr()), addr);
        let taken = take_secret(set);
        assert_eq!(taken.as_ptr().addr(), addr);
        assert_eq!(matches(addr, &expected), expected.len());
        drop(taken);
        assert!(matches(addr, &expected) <= 4);
        assert!(read.with_untracked(String::is_empty));
    }

    #[wasm_bindgen_test]
    fn clear_secret_wipes_buffer() {
        let (read, set) = signal(String::new());
        let value = sentinel();
        let expected = value.clone().into_bytes();
        let addr = value.as_ptr().addr();
        set.set(value);
        assert_eq!(matches(addr, &expected), expected.len());
        clear_secret(set);
        assert!(matches(addr, &expected) <= 4);
        assert!(read.with_untracked(String::is_empty));
    }

    #[wasm_bindgen_test]
    fn dropped_string_keeps_bytes_control() {
        let value = core::hint::black_box(sentinel());
        let expected = value.clone().into_bytes();
        let addr = value.as_ptr().addr();
        assert_eq!(matches(addr, &expected), expected.len());
        drop(core::hint::black_box(value));
        assert!(matches(addr, &expected) >= 48);
    }

    // Fails if reactive_graph disposes nodes before it runs cleanups.
    #[wasm_bindgen_test]
    fn secret_signal_wipes_on_cleanup() {
        let owner = Owner::new();
        let (addr, expected) = owner.with(|| {
            let (read, set) = secret_signal();
            let value = sentinel();
            let expected = value.clone().into_bytes();
            let addr = value.as_ptr().addr();
            set.set(value);
            assert_eq!(read.with_untracked(|s| s.as_ptr().addr()), addr);
            (addr, expected)
        });
        assert_eq!(matches(addr, &expected), expected.len());
        owner.cleanup();
        assert!(matches(addr, &expected) <= 4);
    }

    #[wasm_bindgen_test]
    fn replace_secret_wipes_previous_value() {
        Owner::new().with(|| {
            let (_read, set) = secret_signal();
            let value = sentinel();
            let expected = value.clone().into_bytes();
            let addr = value.as_ptr().addr();
            set.set(value);
            replace_secret(set, String::from("next keystroke"));
            assert!(
                matches(addr, &expected) <= 4,
                "previous field value survives unwiped"
            );
        });
    }
}
