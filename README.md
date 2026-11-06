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
leptos-nostr-auth = { version = "0.2", features = ["csr"] }
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
leptos-nostr-auth = { version = "0.2", optional = true }

[features]
hydrate = ["leptos-nostr-auth/hydrate", ...]
ssr    = ["leptos-nostr-auth/ssr", ...]
```

The library is SSR-safe: all browser-only code is `cfg`-gated so no `window` or `crypto` access occurs on the server. Session restore is a no-op on the server; it runs only after hydration in the browser.

See the `with-axum-ssr` example for a complete cargo-leptos project layout.

## Feature Flags

Requires Rust 1.89+ (edition 2024).

You must select exactly one rendering mode feature:

| Feature | Use when |
|---|---|
| `csr` | Client-side rendering only (Trunk) |
| `hydrate` | Browser WASM target in SSR+hydrate setup |
| `ssr` | Server binary target in SSR+hydrate setup |

### `insecure_nsec_input` — raw secret key paste (opt-in only)

```toml
leptos-nostr-auth = { version = "0.2", features = ["csr", "insecure_nsec_input"] }
```

Shows a raw `nsec1...` / hex private key input behind a two-click security warning. **Not recommended** for production — any XSS on the page can steal the key. Use a browser extension, passkey, or ncryptsec instead.

## Release Profile

Cargo applies `[profile.*]` only at the workspace root, so this crate cannot set them for your build. For a small CSR wasm bundle, add this to your app's `Cargo.toml` (as in `examples/basic-csr`):

```toml
[profile.release]
opt-level     = "z"
lto           = true
codegen-units = 1
panic         = "abort"
```

With cargo-leptos, keep `panic = "abort"` out of `[profile.release]` so it does not reach the server binary. Put it in a wasm-only profile and select that profile:

```toml
[[workspace.metadata.leptos]]
lib-profile-release = "wasm-release"

[profile.wasm-release]
inherits      = "release"
opt-level     = "z"
lto           = true
codegen-units = 1
panic         = "abort"
```

Do not set `strip = "symbols"`: it removes the `target_features` section, and the wasm-opt pass that Trunk runs then fails on bulk-memory instructions. In `basic-csr`, `opt-level = "z"` shrank the wasm from 2669143 to 1979248 bytes and roughly doubled the ncryptsec decrypt time in Chromium, from about 190-255 ms to about 455 ms, because scrypt runs on the main thread.

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
        use leptos_nostr_auth::nostr::{event::{Kind, UnsignedEvent}, types::Timestamp};
        let now = Timestamp::from_secs((js_sys::Date::now() / 1000.0) as u64);
        let unsigned = UnsignedEvent::new(pubkey, now, Kind::TextNote, [], "Hello Nostr!");
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
| Bunker | Opens a socket to the stored relays, in order, and sends `get_public_key` with the stored client key; verifies pubkey matches |
| Passkey | Calls `navigator.credentials.get()` → biometric → re-derives same key |
| Read-Only | Restores directly from stored hex pubkey |
| ncryptsec | **Not persisted** — user must decrypt again (password not stored) |
| Raw nsec | **Not persisted** — user must paste again |

**Bunker sessions**: restoring a bunker session does **not** replay your bunker's original
pairing secret (which per [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) is
single-use and should already be considered spent). Instead, the library persists the small
local "pairing keypair" generated the first time you connected — the same key your bunker
already recognizes and has authorized. This key is disposable and unrelated to your Nostr
identity key, but it is still a live credential: anyone who can read your app's localStorage
(e.g. via an XSS bug elsewhere on your page) can use it to request signatures until you revoke
that client from your bunker/signer app. This is the same exposure class as a browser session
cookie, not a leaked private key.

Restore sends `get_public_key`, not `connect`, so signers that require a secret still restore.
Behaviour on a revoked client varies by signer: one that answers `get_public_key` to anyone
restores it as authenticated, and it then fails at the first signature.

**Approval links**: a signer can answer a request with an `auth_url`. The request stays pending
and any mounted `NostrAuthModal` shows the URL as an https-only link the user clicks, even while
`open` is false; nothing opens a popup. The request gets `bunker_timeout_secs` plus one 300 s
extension, and the extension applies only while a mounted modal can show the link. A modal
unmounted during the extended wait does not shorten it. Mount one modal: each mounted modal renders
the same link, and one Escape reaches all of them. `NostrAuthProvider` already mounts its own.
A challenge at page load shows the same link while `is_restoring` stays `true`.

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
    pub public_key: Signal<Option<nostr::key::PublicKey>>,
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
    BunkerAuthRequired,

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
[data-nostr-auth-prompt]     { /* signer approval prompt */ }
[data-nostr-auth-url]        { /* signer approval link */ }
```

## Upgrading to 0.2

- The crate now declares `rust-version = "1.89"`; Rust 1.88 fails with a "requires rustc" error.
- Public key types are now nostr 0.45 (`nostr::key::PublicKey`). The crate re-exports `nostr`
  as `leptos_nostr_auth::nostr`, so consumers can use the matching version.
- An `ncryptsec` with `log_n` above 18 is now rejected as `InvalidNcryptsec`, because nostr 0.45
  caps scrypt cost. Re-encrypt the key at a lower cost or use another login method.
- On `wasm32-unknown-unknown`, `EventBuilder` and every other caller of `Timestamp::now` need
  `universal_time::define_time_provider!` in the consumer's binary. This crate defines no time
  provider, so it cannot collide with yours, and it builds events with `UnsignedEvent::new` and
  `js_sys::Date::now()` instead. With rustc 1.99.0 and 1.99.1, a wasm binary that reaches `Timestamp::now`
  without a provider fails at link time (`a time provider is required`). Other toolchains may
  behave the other way: a missing provider could link and then trap at runtime with no build
  warning. Do not assume `EventBuilder` works on wasm without a provider.
- A NIP-46 `auth_url` no longer returns an error containing the URL. The request stays pending and
  a mounted modal shows the link. Direct `BunkerSession` callers mount one closed modal, for example
  `<NostrAuthModal open=false on_auth=... />`; a provider already mounts its own. With no modal
  mounted the request fails at its timeout with the new `NostrAuthError::BunkerAuthRequired`.
- A bunker `sign_event` result now uses `nostr`'s JSON key order, not the order the signer sent.
- `bunker://` errors changed: everything `nostr`'s URI parser rejects, including a bad or missing
  pubkey, is now `InvalidBunkerUri("invalid URI")`. A bad pubkey was `InvalidPublicKey`.
- A raw `+` in a URI secret now decodes to a space. Hex and UUID secrets are unaffected.
- A persisted relay URL that `nostr`'s `RelayUrl` rejects (not `ws`/`wss`, or a second `://`) now
  fails restore, which deletes that session.
- A `bunker://` URI may list at most five relays after duplicates are removed. More are refused.
- `BunkerSession::nip44_encrypt` and `nip44_decrypt` now reject a counterparty that is not a hex
  public key with `InvalidPublicKey`, before anything is sent.

## Development

`nix develop` (or `direnv allow` once) enters a shell with the toolchain pinned by
`rust-toolchain.toml`. `nix flake check` runs clippy, docs and formatting checks; `nix fmt`
formats Rust, Nix and TOML.
