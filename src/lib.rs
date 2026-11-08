//! Leptos Nostr Auth — headless Nostr login modal widget for Leptos applications.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use leptos::prelude::*;
//! use leptos_nostr_auth::{NostrAuthProvider, use_nostr_auth};
//!
//! #[component]
//! fn App() -> impl IntoView {
//!     view! {
//!         <NostrAuthProvider>
//!             <HomePage />
//!         </NostrAuthProvider>
//!     }
//! }
//!
//! #[component]
//! fn HomePage() -> impl IntoView {
//!     let auth = use_nostr_auth();
//!     view! {
//!         <Show when=move || auth.is_authenticated.get()>
//!             <p>"Logged in as " {move || auth.npub.get().unwrap_or_default()}</p>
//!         </Show>
//!         <button on:click=move |_| auth.show_login.run(())>"Login"</button>
//!     }
//! }
//! # fn main() {}
//! ```
//!
//! The [README](https://github.com/Sturnine/leptos-nostr-auth#readme) is the guide: setup, each
//! login method, configuration and security limits.
//!
//! # Feature flags
//!
//! - `csr`, `hydrate`, `ssr` — the Leptos render mode. Enable one per build; the server build of
//!   an SSR app needs `ssr`, where every browser call returns an error.
//! - `insecure_nsec_input` — adds raw nsec/hex key paste, shown only when
//!   <code>[LoginMethod]::RawNsec</code> is in [`NostrAuthConfig::allowed_methods`]. Any XSS on the page can
//!   steal a pasted key. Passkey and ncryptsec sessions also hold the raw key in wasm memory: see
//!   "Security limits" in the README.

// Layout queries on the modal's view tree exceed the default depth limit under `ssr`.
#![recursion_limit = "256"]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// Context provider and reactive auth state.
pub mod context;
/// Login modal UI component.
pub mod modal;
pub(crate) mod platform;
/// Authentication backends (NIP-07, NIP-46, passkey, ncryptsec, read-only).
pub mod signers;
pub(crate) mod storage;

pub use context::{NostrAuthContext, NostrAuthProvider, try_use_nostr_auth, use_nostr_auth};
pub use modal::NostrAuthModal;
pub use nostr;

pub use signers::{BunkerSession, Nip07Handle, PasskeySession, RawKeySession, ReadOnlyHandle};
pub use types::{
    AuthResult, LoginMethod, NostrAuthConfig, NostrAuthError, PersistedMethod, PersistedSession,
};

mod types;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
