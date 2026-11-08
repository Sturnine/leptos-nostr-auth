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
| Raw nsec paste | Only with `insecure_nsec_input` feature, and `LoginMethod::RawNsec` in `allowed_methods` (opt-in) |

Passkeys use the WebAuthn PRF extension with a fixed salt (`"nostr-key-v1"`) to deterministically derive the same secp256k1 key from the same passkey. A synced passkey gives the same key on every device that uses the same RP ID and salt; there is no backup if the passkey is lost. No passwords, no clipboard.

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

The library is SSR-safe: browser-only code is `cfg`-gated or runs only in handlers and Effects, so no `window` or `crypto` access occurs on the server. Session restore is a no-op on the server; it runs only after hydration in the browser.

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

Also list `LoginMethod::RawNsec` in `allowed_methods`: the defaults never include it, so a dependency enabling the feature cannot turn it on in your modal. It shows a raw `nsec1...` / hex private key input behind a two-click security warning. **Not recommended** for production — any XSS on the page can steal the key. Prefer a browser extension or a bunker, where the key stays out of the page. Passkey and ncryptsec sessions avoid pasting a key, but they also hold the raw key in wasm memory: see [Security limits](#security-limits).

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

Do not set `strip = "symbols"`: it removes the `target_features` section, and the wasm-opt pass that Trunk runs then fails on bulk-memory instructions. In `basic-csr`, `opt-level = "z"` shrank the wasm from 2669143 to 1979248 bytes and roughly doubled the ncryptsec decrypt time in Chromium, from about 190-255 ms to about 455 ms, because scrypt runs on the main thread. The decrypt also grows the page's wasm memory by 64 MiB at `log_n = 16` and 256 MiB at 18, and wasm memory never shrinks. On a low-memory phone the allocation at 17 or 18 can fail, which aborts the whole app.

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

    // WebAuthn RP ID. Leave it unset: the default, this page's hostname, is the safe choice.
    rp_id: None,

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

Passkeys are scoped to a **Relying Party ID**. `rp_id` defaults to the page's hostname, and that default is the safe choice. Every origin that can use the RP ID can derive the user's Nostr key after one ordinary passkey prompt, because the PRF salt is public. A parent-domain `rp_id` (or a Related Origins file) therefore hands the key to every host under it. Set one only if you control and trust every such host:

```rust
NostrAuthConfig {
    rp_id: Some("myapp.com".into()), // only if every host under myapp.com is yours and trusted
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

A synced passkey gives the same Nostr identity on every device. The key is scoped to the RP ID and the salt, not to this app: any software that uses salt `nostr-key-v1` on the same RP ID derives the same key. There is no backup: losing or deleting the passkey loses this Nostr identity, so use passkey login for keys you can afford to lose, or keep the identity in a signer that can export it.

**Logging back in.** A stored passkey never prompts on page load. The app stays logged out with the session kept, and the prompt comes from `show_login`:

Call `show_login` from a user gesture, such as a click handler, with nothing deferred before it, so that restoring a passkey takes one tap. Before the user's first interaction with the page it opens the login modal and never prompts. After that the crate does not check that the call is in a gesture: a call from a timer or Effect can prompt where the browser allows it. A failed or cancelled prompt keeps the session and opens the modal.

A second `show_login` while a prompt is up opens the modal without a second prompt, so a hung prompt cannot block other methods.

## Examples

Two runnable examples are included in the `examples/` directory:

| Example | Rendering | Styling | Run |
|---|---|---|---|
| `basic-csr` | CSR (Trunk) | Headless (`data-nostr-*`) | `trunk serve`, then open `http://localhost:3000` |
| `with-axum-ssr` | SSR + Hydrate (cargo-leptos) | Headless | `cargo leptos serve`, then open `http://localhost:3000` |

Both examples show a login button, a restore indicator, a forget-session button and logout. `basic-csr` also signs events.

Open `localhost`, not `127.0.0.1`. The default RP ID is the page's hostname, and WebAuthn refuses an IP address as an RP ID, so creating a passkey on `127.0.0.1` throws `SecurityError`.

## Raw Modal (without context provider)

```rust
let (show, set_show) = signal(false);

view! {
    <button on:click=move |_| set_show.set(true)>"Login"</button>
    <NostrAuthModal
        open=show
        on_auth=move |result: AuthResult| {
            // result: AuthResult::Extension | Bunker | Passkey | ReadOnly | Ncryptsec | RawNsec
            let pubkey = result.public_key();
            // The modal goes back to its method list; closing it is yours.
            set_show.set(false);
        }
        on_close=move |()| set_show.set(false)
    />
}
```

## Working with AuthResult

### AuthResult variants

| Variant | Signing | Notes |
|---|---|---|
| `Extension(Nip07Handle)` | Yes | NIP-07 browser extension |
| `Bunker(Box<BunkerSession>)` | Yes | NIP-46 remote signer / Nostr Connect |
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

**Switching accounts in the extension.** The extension may show its own prompt, then the call fails with `SignerKeyMismatch`, whose text is "Signer is using a different account than this session. Log in again to switch." The crate does not log out, so a signer cannot end a session by returning a bad event, and switching the extension back makes the same session work again. On reload the mismatch fails restore with `SignerKeyMismatch` in `restore_error`, for every method. A signer returning no valid key is not a mismatch: an extension reports `InvalidPublicKey`, or `ExtensionRejected` if the value is not a string, and a bunker `BunkerConnectionFailed`. The session stays stored, logged out, and is retried on next load, or for a passkey on the next login click, so switching back restores it. Extension `nip44_encrypt` and `nip44_decrypt` call `getPublicKey` first and fail the same way, which costs one extra extension call each, and a switch between the two calls is not detected.

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
- `AuthResult` also implements `AsyncNip44`, so NIP-17 and NIP-59 gift-wrap helpers take it. They need
  `nostr`'s `nip59` feature on your side, and on wasm the gift-wrap builders reach `Timestamp::now`,
  which needs the time provider above. On an extension, each NIP-44 call also calls `getPublicKey`,
  so an unwrap makes two of each.
- `nip44_encrypt_async` and `nip44_decrypt_async` return `NostrAuthError`. The `nip59` helpers return
  `nostr::error::Error`: NIP-44 steps are kind `Crypto`, the seal's signature step is kind `Other`, and
  the same downcast above works on both. Other `nip59` failures, such as an event that is not a gift
  wrap, have no `NostrAuthError` as source. Use the downcast, not the kind.

### NIP-44 encryption

One async call works for every login method. Passkey, ncryptsec and raw nsec sessions use `nostr`'s
NIP-44 v2 with the key in memory, and extension and bunker sessions ask their signer.

```rust
use leptos_nostr_auth::nostr::key::PublicKey;

let peer = PublicKey::parse(peer_npub_or_hex)?;
let ciphertext = auth_result.nip44_encrypt(&peer, plaintext).await?;
let plaintext = auth_result.nip44_decrypt(&peer, &ciphertext).await?;
```

| Situation | Result |
| --- | --- |
| Read-only session, any peer | `EncryptionUnavailable` |
| Extension or bunker session on a server, on-curve peer | `EncryptionUnavailable` |
| Off-curve peer, any other session, including a closed bunker | `InvalidPublicKey` |
| Key session: bad payload, wrong key, empty plaintext | `EncryptionFailed(text)` |
| Key session on a server | Works |
| Extension throws, rejects or returns a non-string | `EncryptionFailed(text)` |
| Missing `window`, `nostr`, `nip44` or method | `ExtensionNotFound` |
| `getPublicKey` rejected, thrown or non-string; a malformed or off-curve string; another account | `ExtensionRejected`; `InvalidPublicKey`; `SignerKeyMismatch` |
| Bunker signer refuses or answers with something malformed | `EncryptionFailed(text)` |
| Bunker closed, for a valid peer | `BunkerSessionClosed` |
| Bunker timeout, approval, socket or relay failure | `BunkerTimeout`, `BunkerAuthRequired`, `BunkerConnectionFailed` |

Nothing reaches a signer for an off-curve peer. `PublicKey::from_hex` does not check the curve, so the
crate does, first. From an extension, `InvalidPublicKey` can mean either a bad peer or a malformed or
off-curve `getPublicKey`.

The crate adds no input to an error, but `EncryptionFailed` text may come from the signer: sanitized
and capped at 200 characters on both a bunker and an extension. On a key session it can give a byte position within
a plaintext, never its bytes. Match the variant, not the text.

Decrypting a payload near NIP-44's size limit can need gigabytes of memory, so bound the size of
untrusted payloads first.

## Session Restore

When `persist_session: true` (default), successful logins are cached in localStorage. **Your Nostr identity key is never persisted.** A bunker session does persist its pairing key, a live credential: see Bunker sessions below.

A failed or cancelled prompt never clears the session. Only a logout or a successful login as a different identity does:

| Case | Stored session | Result |
|---|---|---|
| `logout` | Deleted | Logged out; also works while logged out |
| `logout` with the modal open | Deleted | The modal closes and any login in it is cancelled; typed input is discarded |
| Stored passkey at page load | Kept | Logged out, with no prompt. `restore_error` stays `None`, since nothing has failed. The login click restores it |
| Failed or cancelled restore, any method | Kept | Logged out; retried on next load, once per page load, with no timers. A passkey retries on the next login click instead, and its failure also opens the modal |
| Another key on restore, any method | Kept | The other key is never adopted. `restore_error` is `SignerKeyMismatch`. Switching the signer back restores it |
| Extension returns a string that is not a valid key on restore | Kept | `restore_error` is `InvalidPublicKey`. Restores once the extension returns the stored key |
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
| Bunker | Opens a socket to the stored relays, in order, and sends `get_public_key` with the stored client key; the answer must equal the stored key. That does not prove the signer holds the key: see Bunker sessions. |
| Passkey | From the login click only: calls `navigator.credentials.get()` → biometric → re-derives same key, verifies pubkey matches |
| Read-Only | Restores directly from stored hex pubkey, which must be on the curve |
| ncryptsec | **Not persisted** — user must decrypt again (password not stored) |
| Raw nsec | **Not persisted** — user must paste again |

**Bunker sessions**: restoring a bunker session does **not** replay your bunker's original pairing secret (which per [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) is single-use and should already be considered spent). Instead, the library persists the local pairing keypair generated the first time you connected, the key your bunker already recognizes and has authorized. This key is unrelated to your Nostr identity key, but it is a live credential, held in clear in localStorage. Anyone who reads it, including any script on your page, can use it from any machine for whatever the signer allows this client, including `sign_event` and `nip44_decrypt`, until you revoke that client in your bunker or signer app. `logout` does not revoke it: it deletes this browser's copy and closes the session, and a copy taken earlier keeps working. Unlike an `HttpOnly` session cookie, it cannot be hidden from scripts. The stored record also names the signer and relays. A script that once wrote localStorage can point a restored session at its own signer, which then answers `get_public_key` with your public key. Signing through it fails, because signatures are checked. Encryption is the exposure: see the next paragraph. Relays must use `wss://`, except on localhost.

A bunker session encrypts or decrypts only after its signer has produced one valid signature for your key. If the app has not signed anything yet, the first `nip44_encrypt` or `nip44_decrypt` sends one signing request for a short unpublished check event first, which some signers ask you to approve.

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
| Call waiting on another call's reconnect | (n+1)T + 300 s | (n+1)T | 180 s / 480 s |
| Login | (2n+1)T + 600 s | | 930 s with link |
| Restore | 2nT + 300 s | | 600 s with link |

The `is_restoring` signal on `NostrAuthContext` is `true` while restore is in progress. Do not hide
the login button behind it. With a relay down, each load can wait for the bounds above, and an
extension that never answers `getPublicKey` keeps it true with no bound, since NIP-07 calls have no
timeout. A login, a logout, a logout in another tab or an unmount ends it at once.

```rust
// Beside the button, not instead of it
view! {
    <Show when=move || auth.is_restoring.get()>
        <p>"Restoring session…"</p>
    </Show>
    <Show when=move || !auth.is_authenticated.get()>
        <button on:click=move |_| auth.show_login.run(())>"Login"</button>
    </Show>
}
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
- A restore still running when another tab stores a different identity is dropped.
- A page restored from the back/forward cache gets no `storage` event for a logout that happened meanwhile.
- A `restore_error` here can go stale if another tab logs in persistably while this tab stays logged out.
- A persistable login in another tab during a held passkey prompt does not cancel the prompt. Its result lands here while the other identity is stored.

To disable persistence:

```rust
NostrAuthConfig { persist_session: false, ..Default::default() }
```

## Security limits

### `is_authenticated` is not proof of identity

`is_authenticated` and `public_key` say what this page believes, and a script on the page can change what it believes. A read-only session is a pasted `npub` with nothing behind it, so anyone can log in as any key that way. An app server must not trust these values: have the client sign a challenge, and verify the signature on the server.

### Secret keys in the page

Passkey, ncryptsec and raw nsec sessions hold the raw secret key in wasm memory for as long as the session lives. A same-origin script can read that memory, or hook `navigator.credentials.get` and read the PRF output before the crate does, which gives it the key. Extension and bunker sessions keep the identity key out of the page, but a script there can still ask them to sign or decrypt.

### Passkeys and the RP ID

Any page on an origin allowed to use the RP ID can derive the passkey's Nostr key. With the default RP ID that is this host only. With a parent domain it is every host under it.

### A stored bunker session can be redirected

A script that writes localStorage once, then is gone, can point the stored bunker session at a signer of its choosing until logout. See Session Restore, Bunker sessions. It can also replace the stored identity with another one; show the logged-in npub where users compose private messages.

### What is wiped, and what is not

The crate wipes these. Wasm tests read memory back for the helpers, the PRF buffer and `Keys`. That each input uses the helpers is by reading:

- The `String` buffer in a login step's signal, with `zeroize`, when a submit takes it, when a rejected value is cleared and when the step is left. This covers the bunker URI, ncryptsec string, password, secret key and read-only inputs.
- The submit copies of the bunker URI and ncryptsec string.
- The bytes read from the passkey's PRF output.
- A `Keys` value's own secret bytes, on drop. This is `nostr`'s `non_secure_erase`, which is best effort and not `zeroize`.

Nothing here reaches these:

- JS strings: `event.target.value`, the DOM input's value and the credential's `ArrayBuffer`. Emptying a field takes the value off the screen and wipes the signal's buffer. It does not undo a paste, and a script on the page could already have read it, so treat a secret pasted in the wrong field as exposed.
- `prop:value` clones, so a copy of a pasted value can sit in freed memory.
- The hash digest and hash state in the passkey derivation.
- scrypt's scratch buffers during ncryptsec decryption. One of them is a single-iteration PBKDF2 of the password, so a later memory read can test password guesses cheaply.
- Key bytes the compiler moved or copied, the bunker one-time secret in `nostr`'s URI parsing and in this crate's parsed target and handshake, and `nostr`'s decoded bech32 bytes.
- The bunker pairing key's hex strings, made for the stored session, and its copy in localStorage.
- Key-session NIP-44: the per-call conversation key, message keys, plaintext buffers and returned plaintext.
- Clones you hold, including one from `auth.get()`, and any memory snapshot taken before the wipe.

This describes named buffers. It does not show that no other copy exists. Logout ends use of a key; it does not prove the memory is clean.

## Context API

```rust
pub struct NostrAuthContext {
    /// Current auth result; `None` when not logged in.
    pub auth: Signal<Option<AuthResult>>,
    /// Authenticated user's public key.
    pub public_key: Signal<Option<nostr::key::PublicKey>>,
    /// Authenticated user's npub (bech32) or hex pubkey as a `String`.
    pub npub: Signal<Option<String>>,
    /// `true` when logged in. Not proof of identity: see "Security limits".
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
#[non_exhaustive]
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
    // NIP-44: this session cannot encrypt, and a failure in either direction
    EncryptionUnavailable,
    EncryptionFailed(String),
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
[data-nostr-tip]             { /* tip */ }
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
  pubkey, and an off-curve pubkey it accepts, is now `InvalidBunkerUri("invalid URI")`. A bad pubkey was `InvalidPublicKey`.
- A raw `+` in a URI secret now decodes to a space. Hex and UUID secrets are unaffected.
- A persisted relay URL that `nostr`'s `RelayUrl` rejects (not `ws`/`wss`, or a second `://`) now
  fails restore, and the session is kept like any other failed restore.
- A `bunker://` URI may list at most five relays after duplicates are removed. More are refused.
- Bunker relays must use `wss://`, except on localhost. A stored session that names another `ws://` relay no longer restores.
- `AuthResult` now has `nip44_encrypt` and `nip44_decrypt`, async, on every login method, and
  implements `AsyncNip44`. `PasskeySession` and `RawKeySession` gain sync `nip44_*`. New
  `NostrAuthError::EncryptionUnavailable`, for a read-only session and for an extension or bunker
  session on a server, where the stubs returned `SigningFailed`, and `NostrAuthError::EncryptionFailed`.
- `Nip07Handle::nip44_*` and `BunkerSession::nip44_*` now take `peer: &PublicKey`, not a hex string.
  A peer that is not on the curve is `InvalidPublicKey` on every method, before anything is sent.
  Before, an extension was handed whatever it was given, and a bunker path only checked the hex.
- A signer's refusal of `sign_event` is now `SigningFailed(text)`, and of `nip44_encrypt` or
  `nip44_decrypt` is `EncryptionFailed(text)`, not `BunkerConnectionFailed(text)`. A refusal at login
  stays `BunkerConnectionFailed`.
- Logging out, or a login or restore replacing a session, closes that bunker session for good, even
  when the new login is the same identity. Pending requests and later calls on any clone, including
  one kept in your own state, fail with the new `NostrAuthError::BunkerSessionClosed` and never
  reconnect; before, a kept clone reconnected. Retrying cannot succeed. Read the current session from
  `NostrAuthContext::auth` instead of keeping a signer across login changes. A failed login closes
  nothing. `to_persisted_session` and the public fields still read.
- A lost relay socket now fails pending requests with `BunkerConnectionFailed("relay connection lost")` as soon as the browser reports the close, including requests waiting for approval, which need a retry. A relay's close frame with TCP held open can wait for the browser's grace period or a new request, bounded by the request's deadline.
  If the crate replaces a socket while a request waits, the request fails with a text saying the
  signer may still answer; check before retrying a signature.
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
  one: `SigningFailed(msg)` for `signEvent`, `EncryptionFailed(msg)` for `nip44_*`,
  `ExtensionRejected(msg)` for `getPublicKey`.
  Before, it raised an uncaught `TypeError` and the future never finished.
- A stored session of any method is now kept when restore fails for any reason, including another
  key and data that can never restore. The user is logged out, `is_restoring` ends false, and restore
  is retried on next load, or for a passkey on the next login click. Before, most failures deleted it, and an absent or throwing extension left
  `is_restoring` stuck true. An extension that asks on every call now prompts on every load until the
  user forgets the session.
- New `NostrAuthContext::has_saved_session` and `restore_error`, and new
  `NostrAuthError::RestoreMethodNotAllowed`. A stored session whose method left `allowed_methods` no
  longer restores or prompts. A mismatch on restore reports `SignerKeyMismatch` for every method.
  A signer returning no valid key is not a mismatch: an extension returning a malformed or off-curve key string reports `InvalidPublicKey`, where an off-curve one reported `SignerKeyMismatch` before.
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
  `SignerKeyMismatch` on a switch. A missing `nip44` is `ExtensionNotFound`. A throwing or rejecting `getPublicKey` here, or one resolving to a non-string, is `ExtensionRejected(msg)`, and a malformed or off-curve string from it is `InvalidPublicKey`, where an off-curve key was `SignerKeyMismatch` before.
  A throwing or rejecting `nip44`, or a non-string return, is `EncryptionFailed(msg)`. Before, these methods returned only `SigningFailed`.
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
- `PersistedSession`'s `Debug` now prints `bunker_uri` and `bunker_client_secret_hex` as `<redacted>`. Serde output is unchanged.
- `ReadOnlyHandle::from_str` and the read-only step now reject off-curve hex, `npub` and `nprofile`, with new error text. About half of all hex secret keys are also valid public keys. Those are still accepted, shown and persisted as a public key.
- A stored session with an off-curve key no longer restores. `restore_error` is `InvalidPublicKey` and the session is kept under the session rule, so it stays in localStorage until logout or a new login.
- An extension returning a string from `getPublicKey` that is off-curve or unparseable now gets `InvalidPublicKey("the extension returned an invalid public key")` at login, from `nip44_*` and on restore. A non-string stays `ExtensionRejected("expected string pubkey")`. On `nip44_*` and restore an off-curve key was `SignerKeyMismatch`, so an app prompting for an account switch on that variant will not prompt here. `nip44` is not called. The session is kept, and restores once the extension returns the stored key. `sign_event` is unchanged, and still reports `SignerKeyMismatch` for that account after any prompt from the extension. `InvalidPublicKey` in `restore_error` is therefore not proof that a session is dead: do not offer to forget it on the variant alone.
- The secret key and read-only inputs now empty on every submit, and the password input on every submit except one refused for an empty `ncryptsec` field. A mistyped `npub` or `nprofile` must be pasted again. Emptying wipes the signal's buffer only: the DOM value, `event.target.value`, earlier keystrokes' strings and `prop:value` clones remain until collected, and a script on the page could already have read the paste. A secret pasted in the read-only field should be treated as exposed. See [What is wiped](#what-is-wiped-and-what-is-not).
- A bunker URI stays after a failed login, as it did before, in clear text with any secret, until the user leaves the step, including under a restore landing on that step or a removal in another tab with no login running. Retrying a URI whose secret was spent fails with the signer's text and needs a new URI. Whether a signer spends a secret on a failed attempt is unknown. What changed: `InvalidBunkerUri` now empties the field, so a typo there is gone. A secret pasted in this field should be treated as exposed.
- An `ncryptsec` string now stays only after `WrongPassword`, where anyone who reads it can attack it offline at its scrypt cost. `InvalidNcryptsec`, including a pasted `nsec1...` and the `log_n` refusal, empties the field, and the error says why. A secret pasted in this field should be treated as exposed.
- The read-only step has a new warning box on the `data-nostr-warning` hook, ending "Anything rejected is cleared from this field."
- The bunker step has a new one-time-secret hint on the `data-nostr-tip` hook, on every platform, so CSS for that hook now applies off Android too.
- The ncryptsec step has a new sentence: "A value no password can open is cleared from this field."
- The bunker, ncryptsec, password, secret key and read-only inputs now carry `autocomplete="off"` and `spellcheck="false"`. Browsers may ignore `autocomplete="off"`.
- ncryptsec decrypt now starts after two frames, or a 200 ms timer that browsers may throttle in a background tab; best effort, no paint is guaranteed. It started after a 16 ms timer before. scrypt still blocks the main thread.
- `NostrAuthModal`'s `on_auth` and `on_close` now accept closures, as in `on_auth=move |result: AuthResult| ...`. A closure passed this way must be `Send + Sync + 'static`, like one given to `Callback::new`. `Callback::new(|x| ...)` or `Callback::new(|_| ...)` on these props no longer infers its parameter type, so write it: `|x: AuthResult|` or `|_: AuthResult|` on `on_auth`, and `|(): ()|` on `on_close`. `Callback` values and annotated closures need no change.

## Development

`nix develop` (or `direnv allow` once) enters a shell with the toolchain pinned by
`rust-toolchain.toml`. `nix flake check` runs clippy with warnings denied on the native, `ssr`, `hydrate` and `csr` builds (the last three also with `insecure_nsec_input`), docs, the native, `ssr` and wasm tests, example builds, `cargo audit` and formatting; `nix fmt`
formats Rust, Nix and TOML.
