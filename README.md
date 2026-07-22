# leptos-nostr-auth

Headless Nostr authentication modal widget for [Leptos](https://leptos.dev) applications.

Drop-in login modal supporting every Nostr authentication method. Headless — bring your own CSS.

## Login Methods

| Method | When shown |
|---|---|
| Browser Extension (NIP-07) | Alby, nos2x, Nostr KeyX detected |
| Nostr Connect / Bunker (NIP-46) | Always |
| Passkey (WebAuthn PRF) | macOS/iOS: **top position** (Face ID/Touch ID); others: if WebAuthn available |
| Read-Only (npub) | Always |
| Encrypted Key / ncryptsec (NIP-49) | Always |
| Amber deep-link | Android user-agent only |
| Raw nsec paste | Only with `insecure_nsec_input` feature (opt-in) |

Passkeys use the WebAuthn PRF extension with a fixed salt (`"nostr-key-v1"`) to deterministically derive the same secp256k1 key from the same passkey on any device. On Apple devices, passkeys sync silently via iCloud Keychain — no passwords, no clipboard.

## Quick Start (CSR)

```toml
# Cargo.toml
[dependencies]
leptos-nostr-auth = { version = "0.1", features = ["csr"] }
```

```rust
use leptos::prelude::*;
use leptos_nostr_auth::{use_nostr_auth, NostrAuthProvider};

fn main() {
    leptos::mount::mount_to_body(App);
}

#[component]
fn App() -> impl IntoView {
    view! {
        <NostrAuthProvider>
            <HomePage />
        </NostrAuthProvider>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    let auth = use_nostr_auth();
    view! {
        // Show loading state while session restores on mount
        <Show when=move || auth.is_restoring.get() fallback=|| ()>
            <p>"Restoring session…"</p>
        </Show>

        <Show
            when=move || auth.is_authenticated.get()
            fallback=move || view! {
                // Hide login button while restoring to avoid a flash of unauthenticated content
                <Show when=move || !auth.is_restoring.get() fallback=|| ()>
                    <button on:click=move |_| auth.show_login.run(())>
                        "Login with Nostr"
                    </button>
                </Show>
            }
        >
            <p>"Logged in as: " {move || auth.npub.get().unwrap_or_default()}</p>
            <p>"via " {move || auth.auth.get().map(|a| a.method_name()).unwrap_or("")}</p>
            <button on:click=move |_| auth.logout.run(())>"Logout"</button>
        </Show>
    }
}
```

## SSR / cargo-leptos Setup

For server-side rendering with Axum and cargo-leptos, select rendering features per build target:

```toml
# Cargo.toml (cargo-leptos workspace member)
[dependencies]
leptos-nostr-auth = { version = "0.1", optional = true }

[features]
hydrate = ["leptos-nostr-auth/hydrate", ...]
ssr    = ["leptos-nostr-auth/ssr", ...]
```

The library is SSR-safe: all browser-only code is `cfg`-gated so no `window` or `crypto` access occurs on the server. Session restore is a no-op on the server; it runs only after hydration in the browser.

See the `with-axum-ssr` example for a complete cargo-leptos project layout.

## Feature Flags

You must select exactly one rendering mode feature:

| Feature | Use when |
|---|---|
| `csr` | Client-side rendering only (Trunk) |
| `hydrate` | Browser WASM target in SSR+hydrate setup |
| `ssr` | Server binary target in SSR+hydrate setup |

### `insecure_nsec_input` — raw secret key paste (opt-in only)

```toml
leptos-nostr-auth = { version = "0.1", features = ["csr", "insecure_nsec_input"] }
```

Shows a raw `nsec1...` / hex private key input behind a two-click security warning. **Not recommended** for production — any XSS on the page can steal the key. Use a browser extension, passkey, or ncryptsec instead.

## Configuration

```rust
use leptos_nostr_auth::{NostrAuthConfig, LoginMethod};

let config = NostrAuthConfig {
    // Persist session to localStorage (default: true)
    persist_session: true,

    // localStorage key (default: "leptos_nostr_auth_session")
    storage_key: "my_app_nostr_session".to_string(),

    // Close modal on backdrop click (default: true)
    close_on_backdrop_click: true,

    // Close modal on Escape key (default: true)
    close_on_escape: true,

    // REQUIRED for passkey: your domain (no https:// prefix)
    // Default: window.location.hostname
    rp_id: Some("myapp.com".into()),

    // WebAuthn relying party display name (default: "Nostr App")
    rp_name: "My App".to_string(),

    // NIP-46 connection timeout in seconds (default: 30)
    bunker_timeout_secs: 30,

    // Restrict which methods appear in the modal (default: all)
    allowed_methods: vec![
        LoginMethod::Extension,
        LoginMethod::Bunker,
        LoginMethod::Passkey,
        LoginMethod::ReadOnly,
        LoginMethod::Ncryptsec,
    ],

    ..Default::default()
};

view! {
    <NostrAuthProvider config=config>
        <App />
    </NostrAuthProvider>
}
```

## Passkey Setup (macOS / iOS)

Passkeys are scoped to a **Relying Party ID** (your domain). You **must** configure `rp_id`:

```rust
NostrAuthConfig {
    rp_id: Some("myapp.com".into()), // must match window.location.hostname exactly
    ..Default::default()
}
```

Passkeys created on `myapp.com` only work on `myapp.com`. On localhost for development, use `rp_id: Some("localhost".into())`.

**How it works (Roadflare iOS pattern ported to WebAuthn):**

1. Browser calls `navigator.credentials.create()` with PRF extension and salt `"nostr-key-v1"`
2. OS shows Touch ID / Face ID sheet (macOS/iOS) or platform authenticator
3. PRF returns a deterministic 32-byte output
4. SHA-256 of that output becomes the secp256k1 private key
5. Only the passkey credential ID is stored in localStorage — no private key bytes

Same passkey on any device → same Nostr identity. Syncs automatically via iCloud Keychain on Apple, Google Password Manager on Android, Windows Hello on Windows.

## Examples

Two runnable examples are included in the `examples/` directory:

| Example | Rendering | Styling | Run |
|---|---|---|---|
| `basic-csr` | CSR (Trunk) | Headless (`data-nostr-*`) | `trunk serve` |
| `with-axum-ssr` | SSR + Hydrate (cargo-leptos) | Headless | `cargo leptos serve` |

All examples demonstrate: login button, session restore indicator, sign event button, logout.

## Raw Modal (without context provider)

```rust
let (show, set_show) = signal(false);

view! {
    <button on:click=move |_| set_show(true)>"Login"</button>
    <NostrAuthModal
        open=show.into()
        on_auth=move |result| {
            // result: AuthResult::Extension | Bunker | Passkey | ReadOnly | Ncryptsec | RawNsec
            let pubkey = result.public_key();
        }
        on_close=move |_| set_show(false)
    />
}
```

## Working with AuthResult

### AuthResult variants

| Variant | Signing | Notes |
|---|---|---|
| `Extension(Nip07Handle)` | Yes | NIP-07 browser extension |
| `Bunker(BunkerSession)` | Yes | NIP-46 remote signer / Nostr Connect |
| `Passkey(PasskeySession)` | Yes | WebAuthn PRF-derived key, biometric |
| `ReadOnly(ReadOnlyHandle)` | No | Public key only |
| `Ncryptsec(RawKeySession)` | Yes | NIP-49 password-decrypted, in-memory |
| `RawNsec(RawKeySession)` | Yes | Raw nsec paste (`insecure_nsec_input` only) |

### Public key and method name

```rust
let auth = use_nostr_auth();

// Bech32 npub (or hex fallback) — no boilerplate needed
let npub: Signal<Option<String>> = auth.npub;

// Check auth method for display
if let Some(result) = auth.auth.get() {
    let method = result.method_name(); // "Browser Extension", "Passkey", etc.
}
```

### Signing events

```rust
use leptos_nostr_auth::AuthResult;

// Check if this session can sign (false only for Read-Only)
if auth.auth.get().map(|a| a.can_sign()).unwrap_or(false) {
    if let Some(auth_result) = auth.auth.get() {
        let pubkey = auth_result.public_key();
        let unsigned = nostr::EventBuilder::new(nostr::Kind::TextNote, "Hello Nostr!")
            .build(pubkey);
        let event_json = unsigned.as_json();

        // Unified async API — works for all signing methods
        wasm_bindgen_futures::spawn_local(async move {
            match auth_result.sign_event(&event_json).await {
                Ok(signed_json) => { /* publish to relays */ }
                Err(e) => { /* show error */ }
            }
        });
    }
}
```

### NIP-44 encryption

```rust
// NIP-07 extension
if let AuthResult::Extension(handle) = &auth_result {
    let ciphertext = handle.nip44_encrypt(recipient_hex, plaintext).await?;
    let plaintext  = handle.nip44_decrypt(sender_hex, ciphertext).await?;
}

// NIP-46 bunker — also supports nip44_encrypt / nip44_decrypt
if let AuthResult::Bunker(session) = &auth_result {
    let ciphertext = session.nip44_encrypt(recipient_hex, plaintext).await?;
}
```

## Session Restore

When `persist_session: true` (default), successful logins are cached in localStorage. **Private keys are never persisted.**

| Method | Restore behavior |
|---|---|
| Extension | Re-calls `window.nostr.getPublicKey()`, verifies pubkey matches |
| Bunker | Re-establishes WebSocket connection using stored `bunker://` URI |
| Passkey | Calls `navigator.credentials.get()` → biometric → re-derives same key |
| Read-Only | Restores directly from stored hex pubkey |
| ncryptsec | **Not persisted** — user must decrypt again (password not stored) |
| Raw nsec | **Not persisted** — user must paste again |

The `is_restoring` signal on `NostrAuthContext` is `true` while restore is in progress.
Use it to suppress the login button flash:

```rust
// Don't show the login button during session restore
<Show when=move || !auth.is_restoring.get() && !auth.is_authenticated.get()>
    <button on:click=...>"Login"</button>
</Show>
```

To disable persistence:

```rust
NostrAuthConfig { persist_session: false, ..Default::default() }
```

## Context API

```rust
pub struct NostrAuthContext {
    /// Current auth result; `None` when not logged in.
    pub auth: Signal<Option<AuthResult>>,
    /// Authenticated user's public key.
    pub public_key: Signal<Option<nostr::PublicKey>>,
    /// Authenticated user's npub (bech32) or hex pubkey as a `String`.
    pub npub: Signal<Option<String>>,
    /// `true` when logged in.
    pub is_authenticated: Signal<bool>,
    /// `true` while a persisted session is being restored from localStorage on mount.
    pub is_restoring: Signal<bool>,
    /// Open the login modal programmatically.
    pub show_login: Callback<()>,
    /// Log out and clear the stored session.
    pub logout: Callback<()>,
}
```

### `use_nostr_auth()`

Returns `NostrAuthContext`. Panics if called outside a `NostrAuthProvider`.

### `try_use_nostr_auth()`

Non-panicking variant. Returns `None` outside a `NostrAuthProvider`:

```rust
if let Some(auth) = try_use_nostr_auth() {
    // inside a provider
}
```

## Error Types

All fallible operations return `NostrAuthError`:

```rust
pub enum NostrAuthError {
    // NIP-07 extension
    ExtensionNotFound,
    ExtensionRejected(String),

    // Keys / public key parsing
    InvalidPublicKey(String),

    // NIP-46 bunker
    InvalidBunkerUri(String),
    BunkerConnectionFailed(String),
    BunkerTimeout,

    // WebAuthn passkey
    PasskeyFailed(String),
    PasskeyNotSupported,

    // NIP-49 ncryptsec
    InvalidNcryptsec(String),
    WrongPassword,

    // Raw nsec (insecure_nsec_input feature)
    InvalidSecretKey(String),

    // Signing
    SigningFailed(String),

    // Internal serialization
    Serialization(String),
}
```

## Headless CSS Hooks

All elements emit `data-nostr-*` attributes for styling:

```css
[data-nostr-backdrop]        { /* modal overlay */ }
[data-nostr-modal]           { /* modal box */ }
[data-nostr-modal-title]     { /* "Connect to Nostr" heading */ }
[data-nostr-method]          { /* login method button */ }
[data-nostr-method-icon]     { /* method icon wrapper */ }
[data-nostr-method-title]    { /* method name */ }
[data-nostr-method-subtitle] { /* method description */ }
[data-nostr-badge]           { /* "Recommended" badge */ }
[data-nostr-error]           { /* error message */ }
[data-nostr-warning]         { /* security warning */ }
[data-nostr-input]           { /* text inputs */ }
[data-nostr-spinner]         { /* loading spinner */ }
[data-nostr-back]            { /* back button */ }
[data-nostr-close]           { /* close button */ }
```
