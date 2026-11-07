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
//! # Feature flags
//!
//! - `insecure_nsec_input` — enables raw nsec/hex key paste (XSS risk; opt-in only). Passkey and
//!   ncryptsec sessions also hold the raw key in wasm memory: see "Security limits" in the README.

// Layout queries on the modal's view tree exceed the default depth limit under `ssr`.
#![recursion_limit = "256"]

/// Context provider and reactive auth state.
pub mod context;
/// Login modal UI component.
pub mod modal;
/// Platform capability detection (browser APIs, user-agent).
pub(crate) mod platform;
/// Authentication backends (NIP-07, NIP-46, passkey, ncryptsec, read-only).
pub mod signers;
/// Session restore logic (reads `PersistedSession` and reconnects the signer).
pub(crate) mod storage;

// Public re-exports
pub use context::{NostrAuthContext, NostrAuthProvider, try_use_nostr_auth, use_nostr_auth};
pub use modal::NostrAuthModal;
pub use nostr;

// Core types
pub use signers::{BunkerSession, Nip07Handle, PasskeySession, RawKeySession, ReadOnlyHandle};
pub use types::{
    AuthResult, LoginMethod, NostrAuthConfig, NostrAuthError, PersistedMethod, PersistedSession,
};

/// Core types: auth results, login methods, configuration, and errors.
mod types;
