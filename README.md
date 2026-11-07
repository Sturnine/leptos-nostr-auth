# leptos-nostr-auth

Headless Nostr authentication modal widget for [Leptos](https://leptos.dev) applications.

Drop-in login modal supporting every Nostr authentication method. Headless — bring your own CSS.

## Login Methods

| Method | When shown |
|---|---|
| Browser Extension (NIP-07) | Alby, nos2x, Nostr KeyX, detected each time the modal opens |
| Nostr Connect / Bunker (NIP-46) | Always |
| Passkey (WebAuthn PRF) | macOS/iOS: **top position** (Face ID/Touch ID); others: if WebAuthn available |
| Read-Only (npub) | Always |
| Encrypted Key / ncryptsec (NIP-49) | Always |
| Raw nsec paste | Only with `insecure_nsec_input` feature (opt-in) |

Passkeys use the WebAuthn PRF extension with a fixed salt (`"nostr-key-v1"`) to deterministically derive the same secp256k1 key from the same passkey. A synced passkey gives the same key on devices using this crate with the same RP ID. No passwords, no clipboard.

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
        // A restore can wait a long time, so the login button stays available beside this
        <Show when=move || auth.is_restoring.get() fallback=|| ()>
            <p>"Restoring session…"</p>
        </Show>

        <Show
            when=move || auth.is_authenticated.get()
            fallback=move || view! {
                <button on:click=move |_| auth.show_login.run(())>
                    "Login with Nostr"
                </button>
                // Without this, a kept session that cannot restore leaves users no way out
                <Show when=move || auth.has_saved_session.get() fallback=|| ()>
                    <button on:click=move |_| auth.logout.run(())>
                        "Forget saved session"
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

    // WebAuthn relying party ID (no https:// prefix). Set it to share passkeys across subdomains.
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

## Passkey Setup

Passkeys are scoped to a **Relying Party ID**. `rp_id` defaults to the page's hostname. Set it to share credentials across subdomains:

```rust
NostrAuthConfig {
    rp_id: Some("myapp.com".into()), // this host, or a registrable-domain suffix of it
    ..Default::default()
}
```

The RP ID must equal the host or be a registrable-domain suffix of it, and cannot be a public suffix. So `myapp.com` works on `myapp.com` and `app.myapp.com`, while a credential created under `app.myapp.com` does not work on `myapp.com` or on a sibling host.

Every ceremony sends the RP ID, so changing `rp_id` strands credentials made under the old value, including ones made under the hostname before `rp_id` was set. Reverting the config recovers them.

**How it works:**

1. Browser calls `navigator.credentials.create()` with PRF extension and salt `"nostr-key-v1"`
2. The OS or the authenticator asks the user to verify. Platform authenticators, security keys and cross-device passkeys are all offered
3. PRF returns a deterministic 32-byte output. An authenticator that reports PRF as enabled without output gets a follow-up `get` for the new credential
4. SHA-256 of that output becomes the secp256k1 private key
5. Only the passkey credential ID is stored in localStorage — no private key bytes

A synced passkey gives the same Nostr identity on devices using this crate with the same RP ID. Whether a passkey syncs depends on its provider.

**Logging back in.** A stored passkey never prompts on page load. The app stays logged out with the session kept, and the prompt comes from `show_login`:

Call `show_login` from a user gesture, such as a click handler, with nothing deferred before it, so that restoring a passkey takes one tap. Before the user's first interaction with the page it opens the login modal and never prompts. After that the crate does not check that the call is in a gesture: a call from a timer or Effect can prompt where the browser allows it. A failed or cancelled prompt keeps the session and opens the modal.

A second `show_login` while a prompt is up opens the modal without a second prompt, so a hung prompt cannot block other methods.

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
        on_auth=Callback::new(move |result: AuthResult| {
            // result: AuthResult::Extension | Bunker | Passkey | ReadOnly | Ncryptsec | RawNsec
            let pubkey = result.public_key();
            // The modal goes back to its method list; closing it is yours.
            set_show(false);
        })
        on_close=Callback::new(move |()| set_show(false))
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

### What signing checks

`sign_event` takes the same input on every login method:

- `kind`, `tags`, `content` and `created_at` are required. A missing or invalid one is
  `Serialization`.
- An absent `pubkey` is filled in with the session key. A `pubkey` that differs from it is refused
  with `SigningFailed`, and nothing reaches a signer.
- A preset `id` is allowed if it matches the fields. Otherwise it is refused the same way.

An event from an extension or a bunker is returned only if all of these hold, and the returned JSON
is the verified event, without any extra fields the signer added:

- Its `pubkey` is the session key, else `SignerKeyMismatch`.
- Its `kind`, `tags` (in order), `content` and `created_at` equal the request, else `SigningFailed`.
- Its id and signature verify, else `SigningFailed`.

A return that is not a full event, including an object holding only `sig`, is refused with
`SigningFailed`. It is not completed from the request. Match the variant, since the `SigningFailed`
texts may change.

**Switching accounts in the extension.** The extension shows its own prompt, then the call fails with
`SignerKeyMismatch`, whose text is "Signer is using a different account than this session. Log in
again to switch." The crate does not log out, so a signer cannot end a session by returning a bad
event, and switching the extension back makes the same session work again. On reload the mismatch
fails restore with `SignerKeyMismatch` in `restore_error`, for every method. The session stays stored,
logged out, and is retried on next load, or for a passkey on the next login click, so switching back
restores it. Extension
`nip44_encrypt` and `nip44_decrypt` call `getPublicKey` first and fail the same way, which costs one
extra extension call each, and a switch between the two calls is not detected.

An extension that keeps the supplied `pubkey` while signing with a switched account reports an
invalid signature through `SigningFailed`, not `SignerKeyMismatch`, because its return names the
session key.

These checks catch a switched account or a faulty or dishonest return. They do not protect against a
compromised page, since an extension in the page realm can patch `Promise`, `WebSocket` or
`WebAssembly` before the crate loads, and an extension holding the key can sign anything.

### Using AuthResult as a nostr signer

`AuthResult` implements `nostr`'s `AsyncGetPublicKey` and `AsyncSignEvent`, so it can be passed to
`finalize_async`. Its `Debug` prints the variant and public key only.

```rust
use leptos_nostr_auth::nostr::event::{FinalizeEventAsync, Kind, UnsignedEvent};
use leptos_nostr_auth::nostr::types::Timestamp;

let now = Timestamp::from_secs((js_sys::Date::now() / 1000.0) as u64);
let event = UnsignedEvent::new(auth_result.public_key(), now, Kind::TextNote, [], "hi")
    .finalize_async(&auth_result)
    .await?;
```

`EventBuilder::new(Kind::TextNote, "hi").finalize_async(&auth_result)` reaches `Timestamp::now`,
as does any `nostr` helper that builds through `EventBuilder`, such as NIP-98
`HttpData::to_authorization`. On wasm that needs your own `universal-time = "0.3"` and `js-sys`
dependencies and this provider in your binary crate:

```rust
use core::time::Duration;
use universal_time::{Instant, MonotonicClock, SystemTime, WallClock, define_time_provider};
struct BrowserClock;
impl WallClock for BrowserClock {
    fn system_time(&self) -> SystemTime {
        SystemTime::from_unix_duration(Duration::from_millis(js_sys::Date::now() as u64))
    }
}
impl MonotonicClock for BrowserClock {
    fn instant(&self) -> Instant {
        Instant::from_ticks(Duration::from_millis(js_sys::Date::now() as u64))
    }
}
define_time_provider!(BrowserClock);
```

With rustc 1.99.1 a missing provider was a link error, and `custom_created_at` did not avoid it,
either in a dev build or with `opt-level = "z"` and `lto`. Other toolchains may link and trap at
runtime, so do not assume `EventBuilder` works on wasm without a provider.

- `sign_event_async` returns `NostrAuthError`. `finalize_async` wraps it in `nostr::error::Error`
  with the original as its source: `use core::error::Error as _;` then
  `err.source().and_then(|s| s.downcast_ref::<NostrAuthError>())`. Match
  `NostrAuthError::BunkerSessionClosed` and handle it by re-reading `NostrAuthContext::auth`.
- `get_public_key_async` returns the session's key, not the extension's current account. A switched
  account shows up as `SignerKeyMismatch` when signing.
- A future can move between threads until its first poll. Without `ssr`, one that has suspended must
  stay on its thread. Key, read-only and closed sessions finish in their first poll.
- `nostr` helpers that also require `AsyncNip44`, such as NIP-17 and NIP-59 gift wrap, do not accept
  `AuthResult`.

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

A failed or cancelled prompt never clears the session. Only a logout or a successful login as a different identity does:

| Case | Stored session | Result |
|---|---|---|
| `logout` | Deleted | Logged out; also works while logged out |
| `logout` with the modal open | Deleted | The modal closes and any login in it is cancelled; typed input is discarded |
| Stored passkey at page load | Kept | Logged out, with no prompt. `restore_error` stays `None`, since nothing has failed. The login click restores it |
| Failed or cancelled restore, any method | Kept | Logged out; retried on next load, once per page load, with no timers. A passkey retries on the next login click instead, and its failure also opens the modal |
| Another key on restore, any method | Kept | The other key is never adopted. `restore_error` is `SignerKeyMismatch`. Switching the signer back restores it |
| Stored data can never restore (bad hex, missing fields, bad base64) | Kept | Logged out, with no prompt or network call. `restore_error` says why |
| Stored method removed from `allowed_methods` | Kept | Logged out, with no prompt or network call. `restore_error` is `RestoreMethodNotAllowed` |
| Stored JSON cannot be decoded | Kept | Reads as nothing stored. `logout` removes it |
| New login, persistable method | Overwritten | Replaced by the new login |
| New login, not persistable, same public key | Kept | A reload restores the stored login |
| New login, not persistable, different public key | Cleared after that login succeeds | A reload is logged out rather than returning the old identity |
| New login whose write fails, different public key (quota, for example) | Cleared | A reload is logged out rather than returning the old identity |
| New login whose write fails, same public key | Kept | A reload restores the same identity |
| Login or logout during a restore | Per the rows above | The restore is cancelled, its result is discarded and `is_restoring` ends at once |
| Failed or cancelled login in the modal | Untouched | A restore in flight continues |

With `persist_session: false` the crate writes nothing on login, starts no restore and ignores removal in other tabs. `logout` still deletes the stored session.

**Forget control.** A kept session that cannot restore has no other visible way out, so show one when `has_saved_session` is true and `is_authenticated` is false, and call `logout`. `restore_error` says why it did not restore. Treat its text as untrusted display text: it can carry words from an extension or a relay. After a login whose write failed, with nothing restorable stored, `has_saved_session` reads true with nothing saved until logout, reload or a refetch from another tab's change. Undecodable bytes read as no saved session, so no forget control shows, though `logout` removes them.

| Method | Restore behavior |
|---|---|
| Extension | Re-calls `window.nostr.getPublicKey()`, verifies pubkey matches |
| Bunker | Opens a socket to the stored relays, in order, and sends `get_public_key` with the stored client key; verifies pubkey matches |
| Passkey | From the login click only: calls `navigator.credentials.get()` → biometric → re-derives same key, verifies pubkey matches |
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

`bunker_timeout_secs` (T) applies per relay and per step, so it does not cap a whole call. With n
relays, at most 5, the longest a call can take is:

| Call | Bound | No approval link | T = 30, n = 5: no link / with link |
|---|---|---|---|
| Call that reconnects | (n+1)T + 300 s | (n+1)T | 180 s / 480 s |
| Call waiting on another call's reconnect | 2T + 300 s | 2T | 60 s / 360 s |
| Login | (2n+1)T + 600 s | | 930 s with link |
| Restore | 2nT + 300 s | | 600 s with link |

The `is_restoring` signal on `NostrAuthContext` is `true` while restore is in progress. Do not hide
the login button behind it. With a relay down, each load can wait for the bounds above, and an
extension that never answers `getPublicKey` keeps it true with no bound, since NIP-07 calls have no
timeout. A login, a logout, a logout in another tab or an unmount ends it at once.

```rust
// Beside the button, not instead of it
<Show when=move || auth.is_restoring.get()>
    <p>"Restoring session…"</p>
</Show>
<Show when=move || !auth.is_authenticated.get()>
    <button on:click=...>"Login"</button>
</Show>
```

`is_restoring` is false on the first hydrated render, because server HTML cannot know storage, and
turns true after hydration before any of your Effects read it. A provider mounted later on the
client, and any CSR app, sees it true on its first render when a restorable session is stored. A
stored passkey leaves it false until the login click.

An extension that asks on every call prompts on every load until the user forgets the session.

A cancelled restore clears a bunker approval link at once and closes its socket. A cancelled restore
or login, or a dropped public `create` or `authenticate`, takes a passkey prompt down where the
browser honours it. An extension prompt stays until answered, with its result discarded.

If a restore finishes while the login modal is on its method list, the modal closes. On a login step it stays open over the logged-in page: closing it keeps the restored session, and finishing a login there replaces it, by the same rules as any new login. A modal you mount yourself is not affected.

### Other tabs

Any removal of the stored session logs out other tabs, through the browser's `storage` event, and drops their in-memory keys. There is no reason signal. A bunker session there closes for good. This covers another tab's `logout`, its login as a different identity with a method that cannot persist, and its quota-failure clear. Limits:

- A removal cancels a login running in this tab's modal and closes the modal, with no reason shown, and a bunker login's one-time secret may be spent, so a retry can need a new URI. With no login running the modal stays open with what was typed, and submitting it is a new login.
- A persistable login elsewhere leaves this tab logged in, but a non-persistable one logs it out. This tab also logs out if that login is the identity it already holds.
- Removing a key that is not there fires no `storage` event. If nothing is stored, a logout in another tab does not reach this one, and this tab keeps its in-memory keys.
- `localStorage.clear()` in another tab logs this tab out if the browser fires a `storage` event for it, even if no session of ours was stored, because the event does not say what was removed. An in-memory ncryptsec or nsec login ends too, and a bunker session closes for good. Use `removeItem` for your own keys. Chromium fires no event when the origin's storage was already empty.
- Undecodable bytes under our key count the same: `removeItem` or `clear()` of them logs this tab out, though nothing was restorable.
- A page restored from the back/forward cache gets no `storage` event for a logout that happened meanwhile.
- A `restore_error` here can go stale if another tab logs in persistably while this tab stays logged out.
- A persistable login in another tab during a held passkey prompt does not cancel the prompt. Its result lands here while the other identity is stored.

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
    /// `true` while a persisted session is being restored: from localStorage on mount, or for a
    /// passkey, from the login click. False on the first hydrated render and at load for a stored
    /// passkey. Do not hide the login button behind it.
    pub is_restoring: Signal<bool>,
    /// `true` when localStorage holds a decodable session, restored or not.
    pub has_saved_session: Signal<bool>,
    /// Why the stored session did not restore. `None` for a passkey awaiting the login click.
    /// Untrusted display text.
    pub restore_error: Signal<Option<NostrAuthError>>,
    /// Open the login modal, or restore a stored passkey.
    ///
    /// Call `show_login` from a user gesture, such as a click handler, with nothing deferred before
    /// it, so that restoring a passkey takes one tap. Before the user's first interaction with the
    /// page it opens the login modal and never prompts. After that the crate does not check that
    /// the call is in a gesture: a call from a timer or Effect can prompt where the browser allows
    /// it. A failed or cancelled prompt keeps the session and opens the modal.
    pub show_login: Callback<()>,
    /// Log out, clear the stored session and close a bunker session for good. It also closes the
    /// login modal and cancels a login in it.
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
    BunkerSessionClosed,

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
    // Another key than the session's. As `restore_error`, the session is kept and retried on the next load, or for a passkey on the next login click
    SignerKeyMismatch,

    // Session restore: the stored method is no longer in `allowed_methods`
    RestoreMethodNotAllowed,

    // Internal serialization
    Serialization(String),
}
```

## Headless CSS Hooks

All elements emit `data-nostr-*` attributes for styling:

```css
[data-nostr-backdrop]        { /* modal overlay */ }
[data-nostr-modal]           { /* modal box */ }
[data-nostr-modal-header]    { /* modal header row */ }
[data-nostr-modal-body]      { /* modal content */ }
[data-nostr-modal-title]     { /* "Connect to Nostr" heading */ }
[data-nostr-methods]         { /* method list */ }
[data-nostr-method]          { /* login method button */ }
[data-nostr-method-icon]     { /* method icon wrapper */ }
[data-nostr-method-title]    { /* method name */ }
[data-nostr-method-subtitle] { /* method description */ }
[data-nostr-badge]           { /* "Recommended" badge */ }
[data-nostr-divider]         { /* "More options" divider */ }
[data-nostr-advanced]        { /* "Advanced" disclosure */ }
[data-nostr-step]            { /* one login step, named by its value */ }
[data-nostr-tip]             { /* platform tip */ }
[data-nostr-info]            { /* information note */ }
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
  warning. Do not assume `EventBuilder` works on wasm without a provider. This includes
  `EventBuilder::finalize_async` and `nostr` helpers that build through it, and
  `custom_created_at` did not avoid the link error with rustc 1.99.1, in a dev build or with
  `opt-level = "z"` and `lto`.
- `AuthResult` now implements `nostr`'s `AsyncGetPublicKey`, `AsyncSignEvent` and `Debug`. `Debug`
  prints the variant and public key only.
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
- A signer's refusal of `sign_event`, `nip44_encrypt` or `nip44_decrypt` is now
  `SigningFailed(text)`, not `BunkerConnectionFailed(text)`. A refusal at login stays
  `BunkerConnectionFailed`.
- Logging out, or a login or restore replacing a session, closes that bunker session for good, even
  when the new login is the same identity. Pending requests and later calls on any clone, including
  one kept in your own state, fail with the new `NostrAuthError::BunkerSessionClosed` and never
  reconnect; before, a kept clone reconnected. Retrying cannot succeed. Read the current session from
  `NostrAuthContext::auth` instead of keeping a signer across login changes. A failed login closes
  nothing. `to_persisted_session` and the public fields still read.
- A lost relay socket now fails pending requests at once with
  `BunkerConnectionFailed("relay connection lost")`, including requests waiting for approval, which
  need a retry.
- A pending request can fail with that same error once another request on the socket has timed out
  and a new request arrives, because the new request reconnects. A request waiting on a verified
  approval link keeps the socket instead.
- A call waiting on another call's reconnect gets `BunkerConnectionFailed("reconnect cancelled")` if
  that call's future is dropped.
- Events returned by an extension or a bunker are now checked. Another key is the new
  `NostrAuthError::SignerKeyMismatch`. A changed `kind`, `tags`, `content` or `created_at`, a wrong
  id or a bad signature is `SigningFailed`, so an extension that rewrites a field now fails every
  signature. Before, all of these returned `Ok`.
- A malformed return through the trait is now `SigningFailed("signer returned an invalid event")`,
  without the parser's text.
- A request whose `pubkey` differs from the session, or whose preset `id` does not match its fields,
  is now `SigningFailed("event pubkey differs from the session key")` or
  `SigningFailed("event id does not match its fields")` on every method, and a remote signer never
  sees it. Before, a remote signer could return `Ok`, and local keys failed with `nostr`'s text.
- Local keys now fill in an absent `pubkey`, where they returned `Serialization`. Duplicate JSON keys
  in a local request now take the last value, where they were a serde error.
- Extension requests now go through the same parsing as other methods. Malformed JSON is
  `Serialization`, not `SigningFailed("invalid event JSON: ..")`. A missing field, `id:""`,
  `pubkey:null`, a non-string tag element, an empty tag, a `kind` above 65535 or a non-integer
  `created_at` is `Serialization` with nothing sent. Unknown request fields are dropped.
- A direct `Nip07Handle::sign_event` no longer returns `Ok("")`, `Ok("null")` or an object missing a
  field, including `{"sig":..}`. All are `SigningFailed("signer returned an invalid event")`.
- A `Nip07Handle::sign_event` result now uses `nostr`'s JSON key order, with extra fields removed.
- An extension that rejects with a non-Error object now gives the static text "extension rejected the
  request", not a dump of the object.
- A missing `window.nostr`, `nip44` or method, or a non-callable one, is now always
  `ExtensionNotFound`, including from `Nip07Handle::get_public_key`. Before, it raised an uncaught
  `TypeError` and the future never finished.
- A present extension method that throws synchronously is now a rejection, the same as an asynchronous
  one: `SigningFailed(msg)` for `signEvent` and `nip44_*`, `ExtensionRejected(msg)` for `getPublicKey`.
  Before, it raised an uncaught `TypeError` and the future never finished.
- A stored session of any method is now kept when restore fails for any reason, including another
  key and data that can never restore. The user is logged out, `is_restoring` ends false, and restore
  is retried on next load, or for a passkey on the next login click. Before, most failures deleted it, and an absent or throwing extension left
  `is_restoring` stuck true. An extension that asks on every call now prompts on every load until the
  user forgets the session.
- New `NostrAuthContext::has_saved_session` and `restore_error`, and new
  `NostrAuthError::RestoreMethodNotAllowed`. A stored session whose method left `allowed_methods` no
  longer restores or prompts. A mismatch on restore reports `SignerKeyMismatch` for every method.
- A login or logout now cancels a restore in flight, and its result is discarded. Before, a late
  result could log a user back in or delete a session a login had just saved.
- A login with a method that cannot persist, as a different identity, now clears the stored session,
  so a reload no longer returns the old identity. So does a login whose write fails.
- Any removal of the stored session now logs out other tabs, including a different-identity
  non-persistable login, the quota-failure clear and `localStorage.clear()` when nothing of ours was
  stored. A bunker session there closes for good. A persistable login elsewhere does not log them out,
  and a logout with nothing stored does not reach them.
- `is_restoring` is now true on the first render with a restorable session, except on the first
  hydrated render and for a stored passkey, which leaves it false until the login click. Stop hiding the
  login button behind it: it can stay true for a long time, or without bound with an extension that
  never answers.
- Extension `nip44_encrypt` and `nip44_decrypt` now call `getPublicKey` first and return
  `SignerKeyMismatch` on a switch. A missing `nip44` is `ExtensionNotFound`. A throwing or rejecting
  `getPublicKey` here is `ExtensionRejected(msg)`, and a malformed key from it is `InvalidPublicKey`;
  these two are new, since these methods only returned `SigningFailed` before.
- A stored passkey no longer prompts on page load. `show_login` starts a passkey prompt when a passkey session is stored, unless the user has not interacted with the page yet.
- `PasskeySession::authenticate` now takes `rp_id` first: `authenticate(rp_id, credential_id)`. It always sends `rpId`.
- `create` no longer filters on `authenticatorAttachment`, so security keys and cross-device passkeys are offered. An authenticator without PRF reaches `create`, gets `PasskeyNotSupported` and leaves a credential behind on each retry. The variant's text is now "This browser or authenticator does not support the WebAuthn PRF extension".
- `create` now completes through a follow-up `get` when the authenticator reports `prf.enabled` with no output. If that fails, the error says to use the existing passkey.
- The passkey option is hidden when `PublicKeyCredential` is absent, or `getClientCapabilities()` reports `extension:prf` as false. An unknown capability keeps it.
- A passkey created under a configured `rp_id` now logs in on a subdomain. A site with no configured `rp_id` sees no change.
- The modal always reopens on its method list, including after a login with a modal you keep open.
- Close, Escape, backdrop, Back, a parent closing `open`, and unmount cancel a login. A late approval or failure never reaches `on_auth` or the error line. A login's approval link clears when it is cancelled. A cancelled bunker login may have spent its one-time secret, so a retry can need a new URI.
- `logout` also closes the provider's modal and cancels a login in it, discarding typed input. `logout` then `show_login` reopens on the list.
- A session removal in another tab cancels a login running in this tab's modal and closes it, with no reason shown. With no login running the modal stays open with what was typed, and submitting it is a new login.
- A restore landing closes the provider's modal only on its method list. On a login step it stays open. A modal you mount yourself is not affected.
- Escape with a modal closed no longer fires `on_close`.
- The Amber method button is gone; use Nostr Connect. The Android tip stays in that step.
- The built-in restore indicator and its `[data-nostr-restoring]` hook are gone. Render your own from `is_restoring`.
- The extension is re-detected each time the modal opens.
- Dropping the future of `PasskeySession::create` or `authenticate` now aborts the browser prompt, where the browser honours it. Keep polling it, or spawn it, to keep the prompt up.
- The Apple passkey subtitle no longer claims iCloud sync.
- `rpId` is now always sent, so changing `rp_id` strands credentials made under the old value, including ones made under the hostname before `rp_id` was set. Reverting the config recovers them.

## Development

`nix develop` (or `direnv allow` once) enters a shell with the toolchain pinned by
`rust-toolchain.toml`. `nix flake check` runs clippy, docs and formatting checks; `nix fmt`
formats Rust, Nix and TOML.
