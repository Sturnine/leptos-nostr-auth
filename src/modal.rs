#![expect(
    clippy::exhaustive_structs,
    reason = "#[component] generates the props structs, which cannot take attributes"
)]
#![cfg_attr(
    not(test),
    expect(
        clippy::missing_docs_in_private_items,
        reason = "#[component] generates the props structs, which cannot take attributes"
    )
)]
use leptos::portal::Portal;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_use_event_listener::use_event_listener;
use leptos_use_window::use_window;

use crate::platform::{Os, Platform, effective_rp_id, passkey_option_visible, prf_capability};
use crate::signers::{
    BunkerSession, Nip07Handle, PasskeySession, PendingPasskey, RawKeySession, ReadOnlyHandle,
    current_auth_url, dismiss_auth_prompt, register_auth_presenter, unregister_auth_presenter,
};
use crate::types::{AuthResult, LoginMethod, NostrAuthConfig, NostrAuthError};

/// Which form is currently shown inside the modal.
#[derive(Clone, PartialEq)]
enum ModalStep {
    /// Login method picker list.
    MethodSelect,
    /// NIP-07 browser extension flow.
    Extension,
    /// NIP-46 bunker URI entry flow.
    Bunker,
    /// WebAuthn passkey flow.
    Passkey,
    /// Read-only public key entry flow.
    ReadOnly,
    /// NIP-49 ncryptsec password entry flow.
    Ncryptsec,
    /// Security warning shown before the raw nsec entry step.
    #[cfg(feature = "insecure_nsec_input")]
    RawNsecWarn,
    /// Raw nsec / hex key paste flow (requires `insecure_nsec_input`).
    #[cfg(feature = "insecure_nsec_input")]
    RawNsec,
}

impl ModalStep {
    /// Header title displayed while this step is active.
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

/// Sub-step within the passkey flow.
#[derive(Clone, PartialEq)]
enum PasskeySubStep {
    /// Choose between creating a new passkey or authenticating with an existing one.
    Choose,
    /// WebAuthn ceremony in progress.
    Loading,
}

/// The Nostr login modal widget.
///
/// Can be used standalone (you manage the `open` signal) or via [`NostrAuthProvider`].
///
/// # Example
/// ```rust,ignore
/// let (show, set_show) = signal(false);
/// view! {
///     <button on:click=move |_| set_show.set(true)>"Login"</button>
///     <NostrAuthModal
///         open=show.into()
///         on_auth=move |result| { /* handle AuthResult */ }
///     />
/// }
/// ```
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
    on_auth: Callback<AuthResult>,
    /// Optional close callback (triggered by backdrop click / Escape key).
    #[prop(optional)]
    on_close: Option<Callback<()>>,
    /// Library configuration.
    #[prop(optional)]
    config: Option<NostrAuthConfig>,
) -> impl IntoView {
    let config = StoredValue::new(config.unwrap_or_default());

    register_auth_presenter();
    on_cleanup(unregister_auth_presenter);

    // Starts as server_default (all methods visible, no platform bias) → Effect
    // updates to real browser capabilities after hydration so the UI narrows reactively.
    // Effects don't run on the server, so SSR always renders the full method list.
    let (platform, set_platform) = signal(Platform::server_default());
    Effect::new(move |_| {
        let detected = Platform::detect();
        set_platform.set(detected);
        spawn_local(async move {
            if !passkey_option_visible(detected.supports_webauthn, prf_capability().await) {
                set_platform.update(|platform| platform.supports_webauthn = false);
            }
        });
    });

    let (step, set_step) = signal(ModalStep::MethodSelect);
    let (error, set_error) = signal(Option::<String>::None);

    let close = move || {
        set_step.set(ModalStep::MethodSelect);
        set_error.set(None);
        if let Some(cb) = on_close {
            cb.run(());
        }
    };

    // Escape closes the modal; with the modal closed it dismisses the approval link instead.
    let _ = use_event_listener(use_window(), leptos::ev::keydown, {
        move |e| {
            if e.key() == "Escape" && config.get_value().close_on_escape {
                if !open.get_untracked() && untrack(current_auth_url).is_some() {
                    dismiss_auth_prompt();
                } else {
                    close();
                }
            }
        }
    });

    view! {
        <Portal>
            <Show when=move || open.get()>
                // Backdrop
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
                    // Modal box — stop click propagation so backdrop doesn't close when clicking inside
                    <div
                        role="dialog"
                        aria-modal="true"
                        aria-label="Connect to Nostr"
                        data-nostr-modal=""
                        on:click=|e| e.stop_propagation()
                    >
                        <ModalHeader
                            step=step
                            set_step=set_step
                            set_error=set_error
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
                                        on_auth=on_auth
                                        set_error=set_error
                                        set_step=set_step
                                    />
                                }.into_any(),
                                ModalStep::Bunker => view! {
                                    <StepBunker
                                        on_auth=on_auth
                                        set_error=set_error
                                        platform=platform
                                        config=config.get_value()
                                    />
                                }.into_any(),
                                ModalStep::Passkey => view! {
                                    <StepPasskey
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

                        // Error display
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

// ─── Approval link ───────────────────────────────────────────────────────────

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

// ─── Modal Header ────────────────────────────────────────────────────────────

#[component]
fn ModalHeader(
    step: ReadSignal<ModalStep>,
    set_step: WriteSignal<ModalStep>,
    set_error: WriteSignal<Option<String>>,
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
                        on:click=move |_| {
                            set_step.set(ModalStep::MethodSelect);
                            set_error.set(None);
                        }
                    >
                        // ← back arrow (inline SVG)
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

// ─── Step 1: Method Selection ────────────────────────────────────────────────

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

    // Reactive closures: re-evaluate when platform signal changes after hydration
    let show_passkey = move || platform.get().supports_webauthn && passkey_allowed;

    view! {
        <div data-nostr-methods="">

            // ── Apple: passkey first ──────────────────────────────────────────
            <Show when=move || matches!(platform.get().os, Os::Apple) && show_passkey()>
                <MethodButton
                    icon=icon_passkey
                    title="Passkey"
                    subtitle="Face ID / Touch ID · syncs via iCloud Keychain"
                    badge=Some("Recommended")
                    on_click=move || set_step.set(ModalStep::Passkey)
                />
            </Show>

            // ── Browser extension ─────────────────────────────────────────────
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

            // ── Android: Amber hint before generic bunker ─────────────────────
            <Show when=move || matches!(platform.get().os, Os::Android) && show_bunker>
                <MethodButton
                    icon=icon_amber
                    title="Amber"
                    subtitle="Open in Amber signer app via NIP-46"
                    on_click=move || set_step.set(ModalStep::Bunker)
                />
            </Show>

            // ── Nostr Connect (Bunker) ────────────────────────────────────────
            <Show when=move || show_bunker>
                <MethodButton
                    icon=icon_bunker
                    title="Nostr Connect"
                    subtitle="Paste a bunker:// URI from nsecBunker or Amber"
                    on_click=move || set_step.set(ModalStep::Bunker)
                />
            </Show>

            // ── Non-Apple: passkey after bunker ───────────────────────────────
            <Show when=move || !matches!(platform.get().os, Os::Apple) && show_passkey()>
                <MethodButton
                    icon=icon_passkey
                    title="Passkey"
                    subtitle="Windows Hello · Android biometric"
                    on_click=move || set_step.set(ModalStep::Passkey)
                />
            </Show>

            // ── Divider ───────────────────────────────────────────────────────
            <div data-nostr-divider="">
                "More options"
            </div>

            // ── ncryptsec (NIP-49) ────────────────────────────────────────────
            <Show when=move || show_ncryptsec>
                <MethodButton
                    icon=icon_ncryptsec
                    title="Encrypted Key"
                    subtitle="Decrypt an ncryptsec1... key with your password"
                    on_click=move || set_step.set(ModalStep::Ncryptsec)
                />
            </Show>

            // ── Read-Only ─────────────────────────────────────────────────────
            <Show when=move || show_readonly>
                <MethodButton
                    icon=icon_read_only
                    title="Read-Only"
                    subtitle="Paste an npub — browse without posting"
                    on_click=move || set_step.set(ModalStep::ReadOnly)
                />
            </Show>

            // ── Raw nsec (feature-gated) ──────────────────────────────────────
            {advanced}
        </div>
    }
}

// ─── Method Button ────────────────────────────────────────────────────────────

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
            // Chevron
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M9 18l6-6-6-6"/>
            </svg>
        </button>
    }
}

// ─── Icons (inline SVG) ───────────────────────────────────────────────────────

fn icon_extension() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18"/></svg> }
}
fn icon_passkey() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> }
}
fn icon_bunker() -> impl IntoView {
    view! { <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="5" y="11" width="14" height="10" rx="2"/><path d="M12 2a4 4 0 0 1 4 4v5H8V6a4 4 0 0 1 4-4z"/><circle cx="12" cy="16" r="1" fill="currentColor"/></svg> }
}
fn icon_amber() -> impl IntoView {
    view! { <svg data-nostr-icon-amber="" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg> }
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

// ─── Step 2a: Extension ───────────────────────────────────────────────────────

#[component]
fn StepExtension(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
    set_step: WriteSignal<ModalStep>,
) -> impl IntoView {
    let (loading, set_loading) = signal(true);
    let (done, set_done) = signal(false);

    // Shared login attempt — called from both the mount Effect and the "Try again" button.
    let attempt = move || {
        set_error.set(None);
        set_loading.set(true);
        spawn_local(async move {
            match Nip07Handle::get_public_key().await {
                Ok(handle) => {
                    set_done.set(true);
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

    // Trigger extension login immediately on mount
    Effect::new(move |_| attempt());

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
            <Show when=move || !loading.get() && !done.get()>
                <button
                    on:click=move |_| attempt()
                >
                    "Try again"
                </button>
                <button
                    on:click=move |_| set_step.set(ModalStep::MethodSelect)
                >
                    "Choose a different method"
                </button>
            </Show>
        </div>
    }
}

// ─── Step 2b: Bunker (NIP-46) ─────────────────────────────────────────────────

#[component]
fn StepBunker(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
    platform: ReadSignal<Platform>,
    config: NostrAuthConfig,
) -> impl IntoView {
    let (uri, set_uri) = signal(String::new());
    let (loading, set_loading) = signal(false);
    let timeout = config.bunker_timeout_secs;

    let connect = move || {
        let uri_val = uri.get().trim().to_owned();
        if uri_val.is_empty() {
            set_error.set(Some("Please paste a bunker:// URI.".into()));
            return;
        }
        set_error.set(None);
        set_loading.set(true);
        spawn_local(async move {
            match BunkerSession::connect(&uri_val, timeout).await {
                Ok(session) => {
                    set_loading.set(false);
                    // `run` panics on a disposed callback, and a wasm panic stops all later work.
                    // Dropping the value closes the session.
                    let _ = on_auth.try_run(AuthResult::Bunker(Box::new(session)));
                }
                Err(e) => {
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

            // Amber tip — Android only
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
                data-nostr-input="bunker-uri"
                aria-label="Bunker URI"
                on:input=move |e| set_uri.set(event_target_value(&e))
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

// ─── Step 2c: Passkey ─────────────────────────────────────────────────────────

#[component]
fn StepPasskey(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
    config: NostrAuthConfig,
) -> impl IntoView {
    let (sub_step, set_sub_step) = signal(PasskeySubStep::Choose);
    // Store both in StoredValue so they're Copy-accessible across multiple Fn closures
    let rp_id = StoredValue::new(config.rp_id);
    let rp_name = StoredValue::new(config.rp_name);

    let await_ceremony = move |begun: Result<PendingPasskey, NostrAuthError>| match begun {
        Ok(pending) => {
            set_sub_step.set(PasskeySubStep::Loading);
            set_error.set(None);
            spawn_local(async move {
                match pending.finish().await {
                    Ok(session) => on_auth.run(AuthResult::Passkey(session)),
                    Err(e) => {
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
                        await_ceremony(begun);
                    }
                >
                    "Create new Nostr identity"
                </button>

                <button
                    on:click=move |_| {
                        let rp = rp_id.with_value(|rp_id| effective_rp_id(rp_id.as_deref()));
                        // None → discoverable login: browser presents all stored passkeys
                        await_ceremony(PasskeySession::begin_authenticate(&rp, None));
                    }
                >
                    "I already have a Nostr passkey — restore it"
                </button>
            </Show>
        </div>
    }
}

// ─── Step 2d: Read-Only ───────────────────────────────────────────────────────

#[component]
fn StepReadOnly(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (input, set_input) = signal(String::new());

    let submit = move || {
        let val = input.get();
        match val.parse::<ReadOnlyHandle>() {
            Ok(handle) => {
                set_error.set(None);
                on_auth.run(AuthResult::ReadOnly(handle));
            }
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

            <input
                type="text"
                placeholder="npub1... or nprofile1... or 64-char hex"
                data-nostr-input="pubkey"
                aria-label="Public key (npub, nprofile, or hex)"
                on:input=move |e| set_input.set(event_target_value(&e))
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

// ─── Step 2e: ncryptsec (NIP-49) ─────────────────────────────────────────────

#[component]
fn StepNcryptsec(
    on_auth: Callback<AuthResult>,
    set_error: WriteSignal<Option<String>>,
) -> impl IntoView {
    let (ncryptsec, set_ncryptsec) = signal(String::new());
    let (password, set_password) = signal(String::new());
    let (loading, set_loading) = signal(false);

    let decrypt = move || {
        let nc = ncryptsec.get().trim().to_owned();
        let pw = password.get();
        if nc.is_empty() {
            set_error.set(Some("Please paste your ncryptsec1... key.".into()));
            return;
        }
        if pw.is_empty() {
            set_error.set(Some("Please enter your password.".into()));
            return;
        }
        set_error.set(None);
        set_loading.set(true);
        // scrypt is CPU-intensive — run in spawn_local so the spinner renders first
        spawn_local(async move {
            // Yield one frame so the spinner renders before scrypt blocks the thread.
            #[expect(
                clippy::unwrap_used,
                reason = "a Promise executor cannot return a Result, and window exists whenever this module runs in a tab"
            )]
            let promise = js_sys::Promise::new(&mut |resolve, _| {
                let _ = web_sys::window()
                    .unwrap()
                    .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, 16);
            });
            let _ = wasm_bindgen_futures::JsFuture::from(promise).await;

            match RawKeySession::from_ncryptsec(&nc, &pw) {
                Ok(session) => {
                    set_loading.set(false);
                    on_auth.run(AuthResult::Ncryptsec(session));
                }
                Err(e) => {
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
                " encrypted key and enter your password to decrypt it."
            </p>

            <input
                type="text"
                placeholder="ncryptsec1..."
                data-nostr-input="ncryptsec"
                aria-label="ncryptsec encrypted key"
                on:input=move |e| set_ncryptsec.set(event_target_value(&e))
                prop:value=move || ncryptsec.get()
            />

            <input
                type="password"
                placeholder="Password"
                data-nostr-input="ncryptsec-password"
                aria-label="ncryptsec decryption password"
                on:input=move |e| set_password.set(event_target_value(&e))
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

// ─── Step 2f: Raw nsec (feature-gated) ───────────────────────────────────────

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
    let (nsec, set_nsec) = signal(String::new());

    let import = move || {
        let val = nsec.get();
        match RawKeySession::from_nsec_or_hex(&val) {
            Ok(session) => {
                // Zero the signal immediately
                set_nsec.set(String::new());
                set_error.set(None);
                on_auth.run(AuthResult::RawNsec(session));
            }
            Err(e) => set_error.set(Some(e.to_string())),
        }
    };

    view! {
        <div data-nostr-step="nsec">
            <input
                type="password"
                autocomplete="off"
                placeholder="nsec1... or 64-char hex"
                data-nostr-input="nsec"
                aria-label="Secret key (nsec or hex)"
                on:input=move |e| set_nsec.set(event_target_value(&e))
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
