# leptos-nostr-auth

A headless Nostr login modal for [Leptos](https://leptos.dev) 0.8. It ships the markup and
`data-nostr-*` styling hooks, with no CSS.

| Method | Shown when (and listed in `allowed_methods`) | Signs | Restored on reload |
|---|---|---|---|
| Browser Extension (NIP-07) | `window.nostr` exists, checked each time the modal opens | Yes | Yes, asks the extension for its key again |
| Nostr Connect / bunker (NIP-46) | Always. Paste a `bunker://` URI; `nostrconnect://` is not supported | Yes | Yes, through the stored relays |
| Passkey (WebAuthn PRF) | WebAuthn exists and PRF is not reported unsupported. Listed first on macOS and iOS | Yes | Yes, from the next login click only |
| Read-only (npub) | Always | No | Yes |
| Encrypted key (NIP-49 `ncryptsec`) | Always | Yes | No, the user decrypts again |
| Raw `nsec` paste | Only with the `insecure_nsec_input` feature and `LoginMethod::RawNsec` in `allowed_methods` | Yes | No |

## Install

Rust 1.89 or later. Enable one render mode:

| Feature | Use for |
|---|---|
| `csr` | Client-side apps (Trunk) |
| `hydrate` | The browser build of an SSR app |
| `ssr` | The server build of an SSR app. Every browser call returns an error there, and restore runs only in the browser after hydration |
| `insecure_nsec_input` | Optional raw `nsec`/hex key paste. See [Raw nsec paste](#raw-nsec-paste) |

```toml
[dependencies]
leptos = { version = "0.8", features = ["csr"] }
leptos-nostr-auth = { version = "0.2", features = ["csr"] }
js-sys = "0.3" # only for the timestamp in the signing example
```

For cargo-leptos, forward the features from your app's own:

```toml
[features]
hydrate = ["leptos-nostr-auth/hydrate"] # plus leptos/hydrate etc.
ssr = ["leptos-nostr-auth/ssr"]         # plus leptos/ssr etc.
```

## Quick start

```rust,no_run
use leptos::prelude::*;
use leptos_nostr_auth::{AuthResult, NostrAuthProvider, use_nostr_auth};

fn main() {
    leptos::mount::mount_to_body(|| view! { <NostrAuthProvider><Home /></NostrAuthProvider> });
}

#[component]
fn Home() -> impl IntoView {
    let auth = use_nostr_auth();
    view! {
        // Beside the login button, never instead of it: a restore can take minutes
        <Show when=move || auth.is_restoring.get()>
            <p aria-live="polite">"Restoring session…"</p>
        </Show>
        <Show
            when=move || auth.is_authenticated.get()
            fallback=move || view! {
                <button on:click=move |_| auth.show_login.run(())>"Log in with Nostr"</button>
                // A kept session that cannot restore needs a way out
                <Show when=move || auth.has_saved_session.get()>
                    <p>{move || auth.restore_error.get().map(|e| format!("Not restored: {e}"))}</p>
                    <button on:click=move |_| auth.logout.run(())>"Forget saved session"</button>
                </Show>
            }
        >
            <p>"Logged in as " {move || auth.npub.get()}</p>
            <p>"via " {move || auth.auth.with(|a| a.as_ref().map_or("", AuthResult::method_name))}</p>
            <button on:click=move |_| auth.logout.run(())>"Log out"</button>
        </Show>
    }
}
```

`NostrAuthProvider` mounts the modal, restores a saved session and provides `NostrAuthContext`
(`use_nostr_auth()`, which panics outside the provider, or `try_use_nostr_auth()`):

| Field | Meaning |
|---|---|
| `auth` | `Signal<Option<AuthResult>>`, the session. Read it with `.with`: `.get()` clones it, key included |
| `public_key`, `npub` | The logged-in key, typed and as an `npub` string |
| `is_authenticated` | A session is present. Not proof of identity, see [Security limits](#security-limits) |
| `is_restoring` | A saved session is being restored |
| `has_saved_session` | localStorage holds a session, restored or not |
| `restore_error` | Why the saved session did not restore. Untrusted display text |
| `show_login` | Opens the modal, or restores a saved passkey. Call it from a click handler |
| `logout` | Logs out, deletes the saved session, closes the modal and ends a bunker session for good |

The full contracts are on [docs.rs](https://docs.rs/leptos-nostr-auth).

## Using the session

`AuthResult` implements `nostr`'s `AsyncSignEvent`, `AsyncGetPublicKey` and `AsyncNip44`, so it
works with `finalize_async` and the NIP-17/NIP-59 helpers. The crate re-exports `nostr` 0.45 as
`leptos_nostr_auth::nostr`.

```rust,no_run
use leptos::{prelude::*, task::spawn_local};
use leptos_nostr_auth::nostr::event::{FinalizeEventAsync, Kind, UnsignedEvent};
use leptos_nostr_auth::nostr::types::Timestamp;
use leptos_nostr_auth::{AuthResult, use_nostr_auth};

#[component]
fn PostButton() -> impl IntoView {
    let auth = use_nostr_auth();
    let post = move |_| {
        let Some(session) = auth.auth.get_untracked().filter(AuthResult::can_sign) else {
            return;
        };
        spawn_local(async move {
            let now = Timestamp::from_secs((js_sys::Date::now() / 1000.0) as u64);
            let unsigned = UnsignedEvent::new(session.public_key(), now, Kind::TextNote, [], "Hello");
            match unsigned.finalize_async(&session).await {
                Ok(event) => { /* publish `event` */ }
                Err(e) => leptos::logging::warn!("{e}"),
            }
        });
    };
    view! { <button on:click=post>"Post"</button> }
}
```

- `sign_event(&json)` is the same with JSON in and out. The request needs `kind`, `tags`, `content`
  and `created_at`. A missing `pubkey` is filled in, and a different one is refused.
- Events from an extension or bunker are verified. Another key is `SignerKeyMismatch`, usually an
  account switch in the extension. The session stays logged in, so switching back makes it work
  again. Any other altered or invalid event is `SigningFailed`.
- `nip44_encrypt(&peer, text)` and `nip44_decrypt(&peer, ciphertext)` work on every method except
  read-only (`EncryptionUnavailable`). Limit the size of untrusted ciphertext: one near NIP-44's
  maximum can need gigabytes of memory to decrypt.
- Errors are `NostrAuthError`. Match the variant, not the text. Through `finalize_async` the
  original error is the source of `nostr::error::Error`. With `core::error::Error` in scope:
  `err.source().and_then(|s| s.downcast_ref::<NostrAuthError>())`.
- `BunkerSessionClosed` means logout or a new login ended that session. Retrying cannot succeed,
  so read the current one from `auth` again rather than keeping a session across logins.

On `wasm32-unknown-unknown`, `UnsignedEvent::new` needs nothing more. `EventBuilder`, and every
`nostr` helper that builds through it (NIP-98 `HttpData::to_authorization`, gift-wrap builders),
calls `Timestamp::now`, which needs a time provider in your binary. Without one, rustc 1.99 fails
at link time (`a time provider is required`), and `custom_created_at` does not avoid it. Other
toolchains may link and trap at runtime. Add `universal-time = "0.3"` and `js-sys`, then:

```rust,ignore
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

## Configuration

```rust
# use leptos::prelude::*;
use leptos_nostr_auth::{NostrAuthConfig, NostrAuthProvider};

# #[component] fn App() -> impl IntoView {
let config = NostrAuthConfig { rp_name: "My App".to_owned(), ..Default::default() };
view! { <NostrAuthProvider config=config>"…"</NostrAuthProvider> }
# }
```

The defaults suit most apps.

| Field | Default | Notes |
|---|---|---|
| `persist_session` | `true` | With `false` nothing is saved or restored, and other tabs are ignored. `logout` still deletes a saved session |
| `storage_key` | `"leptos_nostr_auth_session"` | localStorage key |
| `allowed_methods` | `LoginMethod::all()` | Methods shown, in order. `all()` never includes `RawNsec`. A saved session of a removed method is kept but not restored (`RestoreMethodNotAllowed`) |
| `close_on_backdrop_click`, `close_on_escape` | `true` | |
| `bunker_timeout_secs` | `30` | Per relay and per step, not per call |
| `rp_id` | `None`: the page's hostname, or `localhost` | Leave it unset. See [Passkeys](#passkeys) |
| `rp_name` | `"Nostr App"` | Shown in the passkey prompt |

`NostrAuthModal` also works without the provider. You own `open`, and it returns to its method
list after a login:

```rust,no_run
# use leptos::prelude::*;
use leptos_nostr_auth::{AuthResult, NostrAuthModal};

# #[component] fn App() -> impl IntoView {
let (open, set_open) = signal(false);
view! {
    <button on:click=move |_| set_open.set(true)>"Log in"</button>
    <NostrAuthModal
        open=open
        on_auth=move |result: AuthResult| {
            let _key = result.public_key();
            set_open.set(false);
        }
        on_close=move |()| set_open.set(false)
    />
}
# }
```

Closing the modal (close button, Escape, backdrop, Back, `open` going false, unmount) cancels a
login in it. A late result never reaches `on_auth`.

## Passkeys

The key is derived from the passkey: the WebAuthn PRF output for the fixed salt `"nostr-key-v1"`,
hashed with SHA-256. Only the credential id is saved. Any authenticator with PRF can be used:
platform, security key or another device.

- **No backup.** Losing the passkey loses the identity. A synced passkey gives the same key on
  every device. Any software using the same salt and RP ID derives the same key.
- **Keep the default `rp_id`.** Every origin allowed to use the RP ID can derive the key after one
  normal prompt. A parent domain such as `myapp.com` therefore gives the key to every host under
  it. Set one only if you control and trust all of them. The RP ID must be the host or a
  registrable suffix of it.
- **Changing `rp_id` strands existing passkeys.** Credentials made under the old value, including
  the hostname default, stop working. Changing it back recovers them.
- **Restoring takes a click.** A saved passkey never prompts on page load. `show_login` prompts
  instead, but only after the user has interacted with the page, and only in browsers that
  report user activation. Otherwise it opens the modal. Call it directly from a click handler:
  the crate does not check for a gesture, so a call from a timer or Effect can prompt where the
  browser allows it. A failed or cancelled prompt keeps the session and opens the modal.
- In development open `http://localhost`, not `127.0.0.1`. WebAuthn refuses an IP address as an
  RP ID (`SecurityError`).

## Bunkers (NIP-46)

- A `bunker://` URI may list up to five relays, which must be `wss://` (`ws://` only on
  localhost). A URI's one-time secret may be spent after a failed or cancelled try, so a retry can
  need a new URI.
- A signer that asks for approval with an `auth_url` gets a link in the modal (never a popup). It
  shows even while the modal is closed. Mount exactly one modal (the provider already has one):
  each mounted modal shows the same link. With none mounted the request fails at its timeout with
  `BunkerAuthRequired`. With a link, a request
  waits an extra 300 s. The longest call bounds are on `bunker_timeout_secs` on docs.rs.
- The first NIP-44 call on a session that has not signed yet first asks the signer to sign an
  unpublished check event. Some signers ask the user to approve it.
- A saved bunker session keeps its pairing key (not the Nostr key) in localStorage, in clear. It
  is a live credential: anyone who reads it can use the signer from anywhere until the client is
  revoked in the signer app. `logout` deletes it but does not revoke it.

## Session restore

A successful login is saved to localStorage, except encrypted-key and raw `nsec` logins. The Nostr
secret key is never saved. The provider restores a saved session on load. A passkey waits for the
next `show_login`.

- **A failed restore keeps the session.** The user is logged out, `restore_error` says why, and
  restore is tried again on the next load. Only `logout`, or a login as a different identity,
  removes it. So show a "forget saved session" button when `has_saved_session` is true and
  `is_authenticated` is false, as in the quick start.
- **Never hide the login button behind `is_restoring`.** With a relay down a restore can take
  minutes, and an extension that never answers keeps it true forever. A login or logout ends it at
  once. It is false on the first hydrated render.
- An extension that asks permission on every call prompts on every load until the user forgets
  the session.
- Removing the saved session in one tab logs out the others.

The full rules, per case and across tabs, are on `NostrAuthProvider` on docs.rs.

## Styling

Every element has a `data-nostr-*` attribute:

```css
[data-nostr-backdrop]        { /* overlay */ }
[data-nostr-modal]           { /* dialog box */ }
[data-nostr-modal-header]    { /* header row */ }
[data-nostr-modal-title]     { /* "Connect to Nostr" */ }
[data-nostr-modal-body]      { /* content */ }
[data-nostr-methods]         { /* method list */ }
[data-nostr-method]          { /* method button */ }
[data-nostr-method-icon]     { /* its icon */ }
[data-nostr-method-title]    { /* its name */ }
[data-nostr-method-subtitle] { /* its description */ }
[data-nostr-badge]           { /* "Recommended" */ }
[data-nostr-divider]         { /* "More options" */ }
[data-nostr-advanced]        { /* "Advanced" disclosure */ }
[data-nostr-step]            { /* a login step; the value names it */ }
[data-nostr-tip]             { /* tip */ }
[data-nostr-info]            { /* note */ }
[data-nostr-warning]         { /* security warning */ }
[data-nostr-error]           { /* error message */ }
[data-nostr-input]           { /* text input */ }
[data-nostr-spinner]         { /* spinner */ }
[data-nostr-back]            { /* back button */ }
[data-nostr-close]           { /* close button */ }
[data-nostr-auth-prompt]     { /* signer approval prompt, shown even with the modal closed */ }
[data-nostr-auth-url]        { /* its link */ }
```

## Raw nsec paste

```toml
leptos-nostr-auth = { version = "0.2", features = ["csr", "insecure_nsec_input"] }
```

The feature alone shows nothing: add `LoginMethod::RawNsec` to `allowed_methods` too. The user
then gets an "Advanced → Secret Key" option behind a warning. Any XSS on the page can steal a
pasted key. Prefer an extension or a bunker, which keep the key out of the page.

## Security limits

- **Serve a strict Content-Security-Policy.** The SSR example sends one.
- **`is_authenticated` is not proof of identity.** A read-only login is any pasted `npub`, and a
  script on the page can change what the page believes. A server must check a signed challenge.
- **Passkey, encrypted-key and raw `nsec` sessions hold the secret key in wasm memory.** A script
  on the page can read it, or read the PRF output by hooking `navigator.credentials.get`.
  Extension and bunker sessions keep the key out, but a script can still ask them to sign or
  decrypt. `auth.get()` copies the key: use `auth.with`.
- **Every origin allowed to use the passkey RP ID can derive the key.** With the default that is
  this host only.
- **A stored bunker session can be redirected.** A script that writes localStorage once can point
  it at its own signer, which then receives NIP-44 plaintext, until logout. It can also swap in
  another identity, so show the logged-in `npub` where users write private messages. Signing still
  fails there, because signatures are checked.

### What is wiped, and what is not

Wiped: the login fields' Rust buffers (on submit, on rejection and on leaving the step), the
submitted bunker URI and `ncryptsec` copies, the passkey PRF bytes, and the key inside `Keys` on
drop (`nostr`'s best-effort `non_secure_erase`).

Not wiped: browser strings (the input's DOM value, `event.target.value`, the credential's
`ArrayBuffer`), `prop:value` clones, the passkey hash state, scrypt's buffers (one allows cheap
password guessing from a memory read), copies the compiler made, the bunker one-time secret
inside `nostr`'s parser, the bunker pairing key's hex strings and localStorage copy, NIP-44 keys
and plaintext on key sessions, and every clone you hold.

Clearing a field does not undo a paste: treat a secret pasted into the wrong field as exposed.
Logout ends use of a key; it does not prove memory is clean.

## Release profile

Cargo reads `[profile.*]` only from your workspace root. For a small wasm bundle:

```toml
[profile.release]
opt-level     = "z"
lto           = true
codegen-units = 1
panic         = "abort"
```

With cargo-leptos, put these in a wasm-only profile (`[profile.wasm-release]` with
`inherits = "release"`, selected by `lib-profile-release = "wasm-release"`), so `panic = "abort"`
does not reach the server. Do not set `strip = "symbols"`: Trunk's wasm-opt then fails on
bulk-memory instructions.

`opt-level = "z"` roughly doubles `ncryptsec` decrypt time (about 0.5 s in Chromium), and scrypt
blocks the main thread. Decrypting also grows wasm memory for good, by 64 MiB at `log_n = 16` and
256 MiB at 18. On a low-memory phone that can abort the app.

## Examples

Run inside `nix develop`, then open `http://localhost:3000`:

| Example | Shows | Run |
|---|---|---|
| [`basic-csr`](https://github.com/Sturnine/leptos-nostr-auth/tree/main/examples/basic-csr) | CSR with Trunk, signing | `cd examples/basic-csr && trunk serve` |
| [`with-axum-ssr`](https://github.com/Sturnine/leptos-nostr-auth/tree/main/examples/with-axum-ssr) | SSR and hydration with cargo-leptos and Axum, a strict CSP | `cd examples/with-axum-ssr && cargo leptos serve` |

## Upgrading from 0.1

The changes most apps hit:

- Rust 1.89 or later. Keys are `nostr` 0.45 types, from `leptos_nostr_auth::nostr`.
- `PasskeySession::authenticate(rp_id, credential_id)` takes `rp_id` first. `nip44_*` on
  `Nip07Handle` and `BunkerSession` take `&PublicKey`, not hex.
- `NostrAuthModal`'s `on_auth` and `on_close` take closures. A `Callback::new(|x| …)` there now
  needs its type written: `|x: AuthResult|`, `|(): ()|`.
- A failed restore keeps the saved session. Add the forget button and stop hiding login behind
  `is_restoring`.
- Logout or a new login ends a bunker session for good, including clones you kept
  (`BunkerSessionClosed`).
- Raw `nsec` paste also needs `LoginMethod::RawNsec` in `allowed_methods`.
- Bunker `ws://` relays are refused except on localhost, and `ncryptsec` keys with `log_n` above 18
  are refused.
- On wasm, `EventBuilder` needs a time provider (see [Using the session](#using-the-session)).
- CSS: `data-nostr-icon-amber` (with the Amber button) and `[data-nostr-restoring]` (with the
  built-in restore indicator) are gone. Style the new `[data-nostr-auth-prompt]`.

The full list, with breaking changes marked, is in
[CHANGELOG.md](https://github.com/Sturnine/leptos-nostr-auth/blob/main/CHANGELOG.md).

## Development

`nix develop` (or `direnv allow`) gives the toolchain from `rust-toolchain.toml`.
`nix flake check` runs clippy, docs, tests (native, `ssr`, wasm, and these README snippets), the
example builds, the MSRV check, `cargo audit` and formatting. `nix fmt` formats.
