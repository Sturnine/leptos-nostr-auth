# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-07

### Changed

- **Breaking:** The crate declares `rust-version = "1.89"`; Rust 1.88 fails with a "requires rustc" error.
- **Breaking:** Public keys are nostr 0.45's `nostr::key::PublicKey`. The crate re-exports the matching `nostr` as `leptos_nostr_auth::nostr`.
- **Breaking:** On `wasm32-unknown-unknown`, `EventBuilder` (including `finalize_async` and the `nostr` helpers that build through it) and every other caller of `Timestamp::now` need `universal_time::define_time_provider!` in the consumer's binary. This crate defines no provider, so it cannot collide with yours; it builds events with `UnsignedEvent::new` and `js_sys::Date::now()`. With rustc 1.99.0 and 1.99.1 a missing provider fails at link time (`a time provider is required`), and `custom_created_at` did not avoid that on 1.99.1, in a dev build or with `opt-level = "z"` and `lto`. Other toolchains might link and then trap at runtime with no warning.
- The `ssr` feature enables `leptos-use-{storage,event-listener,window}/ssr` instead of `leptos-use/ssr`. docs.rs now documents the `ssr` and `insecure_nsec_input` API.
- **Breaking:** Every method checks a sign request before any signer sees it. A `pubkey` other than the session's is `SigningFailed("event pubkey differs from the session key")`, and a preset `id` that does not match the fields is `SigningFailed("event id does not match its fields")`; before, a remote signer could return `Ok` and local keys failed with `nostr`'s text. An absent `pubkey` is filled in, where local keys returned `Serialization`. Duplicate JSON keys take the last value, where local keys gave a serde error.
- **Breaking:** Extension requests are parsed like the others. Malformed JSON is `Serialization`, not `SigningFailed("invalid event JSON: ..")`. A missing field, `id:""`, `pubkey:null`, a non-string tag element, an empty tag, a `kind` above 65535 or a non-integer `created_at` is `Serialization` with nothing sent. Unknown request fields are dropped.
- **Breaking:** Events returned by an extension or a bunker are checked; before, all of these returned `Ok`. Another key is the new `NostrAuthError::SignerKeyMismatch`. An off-curve `pubkey`, a changed `kind`, `tags`, `content` or `created_at`, a wrong id or a bad signature is `SigningFailed`, so an extension that rewrites a field fails every signature. An unparseable result, through the trait or from a direct `Nip07Handle::sign_event` (which returned `Ok("")`, `Ok("null")` or an object missing a field, such as `{"sig":..}`), is `SigningFailed("signer returned an invalid event")` without the parser's text. The returned JSON is `nostr`'s, in its key order and without extra fields, not the signer's.
- **Breaking:** A signer's refusal of `sign_event` is `SigningFailed(text)`, and of `nip44_encrypt` or `nip44_decrypt` `EncryptionFailed(text)`, not `BunkerConnectionFailed(text)`. A refusal at login stays `BunkerConnectionFailed`.
- **Breaking:** `Nip07Handle::nip44_*` and `BunkerSession::nip44_*` take `peer: &PublicKey`, not a hex string. An off-curve peer is `InvalidPublicKey` on every method before anything is sent; before, an extension got whatever it was given and a bunker only checked the hex.
- Extension `nip44_*` fail with `ExtensionNotFound` when `nip44` is missing, without asking for the public key. Otherwise they call `getPublicKey` first: another account is `SignerKeyMismatch`, a throw, rejection or non-string is `ExtensionRejected(msg)`, and a malformed or off-curve string is `InvalidPublicKey`. A throwing or rejecting `nip44`, or a non-string return, is `EncryptionFailed(msg)`. Before, these methods returned only `SigningFailed`.
- An extension `getPublicKey` string that is malformed or off-curve is `InvalidPublicKey("the extension returned an invalid public key")` at login, from `nip44_*` (where `nip44` is not called) and on restore, where an off-curve key was `SignerKeyMismatch`, so an app that prompts for an account switch on that variant will not prompt here. A non-string stays `ExtensionRejected("expected string pubkey")`. The session is kept and restores once the extension returns the stored key; `sign_event` still reports `SignerKeyMismatch` for that account, after any prompt from the extension. `InvalidPublicKey` in `restore_error` therefore does not prove a session is dead: do not offer to forget it on the variant alone.
- An extension that rejects with a non-Error object gives the static text "extension rejected the request", not a dump of the object. The extension is re-detected each time the modal opens.
- **Breaking:** A NIP-46 `auth_url` no longer returns an error containing the URL. The request stays pending and a mounted modal shows the link; a provider mounts its own, and direct `BunkerSession` callers mount one closed modal, such as `<NostrAuthModal open=false on_auth=... />`. With no modal mounted the request fails at its timeout with the new `NostrAuthError::BunkerAuthRequired`.
- **Breaking:** Everything `nostr`'s URI parser rejects in a `bunker://` URI, including a bad or missing pubkey, and an off-curve pubkey it accepts, is `InvalidBunkerUri("invalid URI")`. A bad pubkey was `InvalidPublicKey`. A URI may list at most five relays after duplicates are removed.
- **Breaking:** A persisted relay URL that `nostr`'s `RelayUrl` rejects (not `ws`/`wss`, or a second `://`) fails restore, and the session is kept like any other failed restore.
- **Breaking:** Logging out, or a login or restore replacing a session, closes that bunker session for good, even for the same identity. Pending requests and later calls on any clone, including one in your own state, fail with the new `NostrAuthError::BunkerSessionClosed` and never reconnect, so retrying cannot succeed; before, a kept clone reconnected. Read the current session from `NostrAuthContext::auth` instead of keeping a signer across logins. A failed login closes nothing. `to_persisted_session` and the public fields still read.
- A bunker login moves the relay that worked to the front of the stored `bunker_uri`. A raw `+` in a URI secret decodes to a space; hex and UUID secrets are unaffected.
- A lost relay socket fails pending requests with `BunkerConnectionFailed("relay connection lost")` as soon as the browser reports the close, including requests waiting for approval, which need a retry. A relay's close frame with TCP held open can wait for the browser's grace period or a new request, bounded by the request's deadline.
- Once a request on the socket times out with no answer from the signer, the next request reconnects, unless a pending request is waiting on a verified approval link. The reconnect fails the other pending requests with `BunkerConnectionFailed`, saying the signer may still have received them, so apps do not blindly retry a signature. An expired approval link or an unusable signer answer no longer tears down the socket.
- A bunker request waiting on another request's reconnect waits as long as that reconnect can take and takes it over if that request is cancelled. It fails with `BunkerConnectionFailed("reconnect cancelled")` only after three cancelled attempts.
- **Breaking:** `PasskeySession::authenticate(rp_id, credential_id)` takes `rp_id` first and always sends `rpId`, so changing `rp_id` strands credentials made under the old value, including ones made under the hostname before `rp_id` was set. Reverting the config recovers them.
- A stored passkey no longer prompts on page load. `show_login` starts the prompt when a passkey session is stored, unless the user has not interacted with the page or the browser does not report user activation; then it opens the modal.
- `create` no longer filters on `authenticatorAttachment`, so security keys and cross-device passkeys are offered. An authenticator without PRF gets `PasskeyNotSupported`, now "This browser or authenticator does not support the WebAuthn PRF extension", and leaves a credential behind on each retry; the modal then warns that a passkey may have been saved. When the authenticator reports `prf.enabled` with no output, `create` finishes through a follow-up `get`. Any other failure after a passkey is created says it exists and should be used, not recreated.
- The passkey option is hidden when `PublicKeyCredential` is absent or `getClientCapabilities()` reports `extension:prf` as false. An unknown capability keeps it.
- Dropping the future of `PasskeySession::create` or `authenticate` aborts the browser prompt where the browser honours that. Keep polling or spawn it to keep the prompt up.
- The Apple passkey subtitle no longer claims iCloud sync.
- **Breaking:** `ReadOnlyHandle::from_str` and the read-only step reject off-curve hex, `npub` and `nprofile`, with new error text. About half of all hex secret keys are also valid public keys; those are still accepted, shown and persisted as a public key.
- **Breaking:** An `ncryptsec` with `log_n` above 18 is `InvalidNcryptsec`, because nostr 0.45 caps scrypt cost. Re-encrypt the key at a lower cost or use another login method.
- ncryptsec decrypt starts after two frames or a 200 ms timer, which browsers may throttle in a background tab, instead of a 16 ms timer. No paint is guaranteed, and scrypt still blocks the main thread.
- **Breaking:** `NostrAuthModal`'s `on_auth` and `on_close` accept closures, as in `on_auth=move |result: AuthResult| ...`, which must be `Send + Sync + 'static` like one given to `Callback::new`. `Callback::new(|x| ...)` or `Callback::new(|_| ...)` on these props no longer infers its parameter type, so annotate it: `|x: AuthResult|` or `|_: AuthResult|` on `on_auth`, `|(): ()|` on `on_close`. `Callback` values and annotated closures need no change.
- **Breaking:** A stored session of any method is kept when restore fails for any reason, including another key, an off-curve key and data that can never restore, until logout or a new login. The user is logged out, `is_restoring` ends false, and restore is retried on the next load, or for a passkey on the next login click. Before, most failures deleted it, and an absent or throwing extension left `is_restoring` stuck true. An extension that asks on every call now prompts on every load until the user forgets the session. A stored off-curve key no longer restores; `restore_error` is `InvalidPublicKey`.
- **Breaking:** A stored session whose method was removed from `allowed_methods` no longer restores or prompts. `restore_error` is `RestoreMethodNotAllowed`.
- Any removal of the stored session logs out other tabs, including a different-identity non-persistable login, the quota-failure clear and `localStorage.clear()` when nothing of ours was stored. A bunker session there closes for good. A persistable login elsewhere does not log them out, and a logout with nothing stored does not reach them.
- `is_restoring` is true on the first render with a restorable session, except on the first hydrated render and for a stored passkey, which leaves it false until the login click. Do not hide the login button behind it: it can stay true for a long time, or forever with an extension that never answers.
- The modal always reopens on its method list, including after a login with a modal you keep open.
- Close, Escape, backdrop, Back, a parent closing `open`, and unmount cancel a login, and clear its approval link. A late approval or failure never reaches `on_auth` or the error line. A cancelled bunker login may have spent its one-time secret, so a retry can need a new URI.
- `logout` also closes the provider's modal and cancels a login in it, discarding typed input. `logout` then `show_login` reopens on the list.
- A session removal in another tab cancels a login running in this tab's modal and closes it, with no reason shown. With no login running the modal stays open with what was typed, and submitting it is a new login.
- A restore landing closes the provider's modal only on its method list; on a login step it stays open. A modal you mount yourself is not affected.

### Added

- `AuthResult` implements `nostr`'s `AsyncGetPublicKey`, `AsyncSignEvent` and `AsyncNip44`, and `Debug`, which prints the variant and public key only.
- `AuthResult::nip44_encrypt` and `nip44_decrypt`, async, on every login method, and sync `nip44_*` on `PasskeySession` and `RawKeySession`. New `NostrAuthError::EncryptionFailed`, and `NostrAuthError::EncryptionUnavailable` for a read-only session and for an extension or bunker session on a server, where the stubs returned `SigningFailed`.
- `NostrAuthContext::has_saved_session` and `restore_error`, and `NostrAuthError::RestoreMethodNotAllowed`. A key mismatch on restore reports `SignerKeyMismatch` for every method.
- A warning box in the read-only step on the `data-nostr-warning` hook, ending "Anything rejected is cleared from this field."
- A one-time-secret hint in the bunker step on the `data-nostr-tip` hook, on every platform, so CSS for that hook now applies off Android too.
- The approval prompt, `[data-nostr-auth-prompt]` with its link `[data-nostr-auth-url]`, renders from every mounted modal, open or not. Style it.
- A sentence in the ncryptsec step: "A value no password can open is cleared from this field."

### Removed

- **Breaking:** The Amber method button and its `data-nostr-icon-amber` hook; use Nostr Connect. The Android tip stays in that step.
- **Breaking:** The built-in restore indicator and its `[data-nostr-restoring]` hook. Render your own from `is_restoring`.

### Fixed

- **Breaking:** A remote signer that answers `connect` with anything but `ack` or the echoed secret is treated as refusing, and its reply is shown, instead of counting as paired. Use a signer that follows NIP-46.
- A session restore that finishes after another tab stored a different identity is dropped instead of logging this tab in as the old identity.
- A missing or non-callable `window.nostr`, `nip44` or method is always `ExtensionNotFound`, including from `Nip07Handle::get_public_key`. A present method that throws synchronously is a rejection, like an asynchronous one: `SigningFailed(msg)` for `signEvent`, `EncryptionFailed(msg)` for `nip44_*`, `ExtensionRejected(msg)` for `getPublicKey`. Before, both raised an uncaught `TypeError` and the future never finished.
- A login or logout cancels a restore in flight and discards its result. Before, a late result could log a user back in or delete a session a login had just saved.
- A login with a method that cannot persist, as a different identity, or whose write fails, clears the stored session, so a reload no longer returns the old identity.
- A passkey created under a configured `rp_id` logs in on a subdomain. A site with no configured `rp_id` sees no change. Every host that can use the RP ID can derive the key, so keep the hostname default unless you trust every such host.
- Escape with a modal closed no longer fires `on_close`.
- A NIP-44 encrypt result from an extension or remote signer that is not a NIP-44 v2 payload, such as NIP-04 output or the plaintext, is `EncryptionFailed` instead of being returned as ciphertext.
- Passkey ceremony errors no longer show a JavaScript debug dump, and a missing or empty credential id is refused instead of stored.
- A bunker timeout on a relay that only sent a NIP-42 challenge no longer claims the relay requires authentication; that diagnosis is kept for relays that refuse with `auth-required:`.

### Security

- **Breaking:** With `insecure_nsec_input` enabled, raw nsec paste also needs `LoginMethod::RawNsec` in `allowed_methods`, which `LoginMethod::all()` and the default no longer include, so a dependency enabling the feature no longer turns it on in every app's default modal.
- **Breaking:** A bunker session encrypts or decrypts only after its signer has produced a valid signature for the account. If the app has not signed yet, the first NIP-44 call of the session sends one signing request for an unpublished check event, which some signers ask the user to approve; a refusal fails the call with `EncryptionFailed`. A stored session pointed at another signer can no longer receive NIP-44 plaintext.
- **Breaking:** A passkey PRF result or credential id that is not a byte buffer is refused. Before, a number was coerced into zero bytes, giving a key anyone could compute. Keys from conforming browsers, and byte buffers from another JavaScript realm, are unchanged. A user whose passkey provider returned anything else can no longer log in or restore with that passkey, and should move the identity to a new key, since the old one may be publicly computable.
- **Breaking:** Bunker URIs that name a plaintext `ws://` relay are refused, except on localhost. A stored bunker session that uses one no longer restores; log in again with a `wss://` relay.
- `PersistedSession`'s `Debug` prints `bunker_uri` and `bunker_client_secret_hex` as `<redacted>`. Serde output is unchanged. The stored bunker URI is built from the session's own signer key and relays, so a secret put back into the public `bunker_uri` field is never persisted.
- Typing in a secret field wipes the previous value instead of leaving each keystroke's prefix in freed memory.
- The secret key and read-only inputs empty on every submit, and the password input on every submit except one refused for an empty `ncryptsec` field, so a mistyped `npub` or `nprofile` must be pasted again. Emptying wipes the signal's buffer only: the DOM value, `event.target.value` and `prop:value` clones remain until collected, and a script on the page could already have read the paste. See [What is wiped](https://github.com/Sturnine/leptos-nostr-auth#what-is-wiped-and-what-is-not).
- `InvalidBunkerUri` empties the bunker URI field. Any other failed login leaves the URI in clear text with any secret, as before, until the user leaves the step, including under a restore landing on that step or a removal in another tab with no login running. Retrying a URI whose secret was spent fails with the signer's text and needs a new URI; whether a signer spends a secret on a failed attempt is unknown.
- An `ncryptsec` string stays only after `WrongPassword`, where anyone who reads it can attack it offline at its scrypt cost. `InvalidNcryptsec`, including a pasted `nsec1...` and the `log_n` refusal, empties the field and says why.
- Treat a secret pasted in the read-only, bunker or ncryptsec field as exposed.
- The bunker, ncryptsec, password, secret key and read-only inputs carry `autocomplete="off"`, which browsers may ignore, and `spellcheck="false"`.
- Relay frames over 256 KiB are dropped before parsing, so a hostile relay cannot grow the page's memory with huge frames.
- Extension error text is sanitized and capped like bunker text, and both also drop line separators, the Arabic letter mark, interlinear annotation and tag characters, and blank Hangul fillers. A relay URL the browser refuses is no longer quoted in the bunker error, so credentials in it are not shown, and `sign_event` errors for malformed event JSON no longer quote the event's values.
- An approval link ignores a primary click for half a second after it appears and names the signer's host, so a hostile signer cannot time it under the user's next primary click. Middle-click and "open in new tab" are not guarded.
- Documented that every origin allowed to use the passkey RP ID can derive the user's Nostr key, that the hostname default is the safe choice, and that a passkey identity has no backup; the examples no longer set `rp_id`. Documented that a bunker restore's matching public key does not prove the signer holds the key, and that a one-time localStorage write can redirect a stored bunker session, or swap in another identity, until logout.
- The examples no longer clone the session in views or keep a signed event across logins, and the SSR example sends a strict Content-Security-Policy.

## [0.1.0] - 2026-07-22

Initial release.

[Unreleased]: https://github.com/Sturnine/leptos-nostr-auth/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Sturnine/leptos-nostr-auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Sturnine/leptos-nostr-auth/releases/tag/v0.1.0
