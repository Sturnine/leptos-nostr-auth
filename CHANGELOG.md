# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-07

### Changed

- **Breaking:** The crate now declares `rust-version = "1.89"`; Rust 1.88 fails with a "requires rustc" error.
- **Breaking:** Public key types are now nostr 0.45 (`nostr::key::PublicKey`). The crate re-exports `nostr`
  as `leptos_nostr_auth::nostr`, so consumers can use the matching version.
- **Breaking:** An `ncryptsec` with `log_n` above 18 is now rejected as `InvalidNcryptsec`, because nostr 0.45
  caps scrypt cost. Re-encrypt the key at a lower cost or use another login method.
- **Breaking:** On `wasm32-unknown-unknown`, `EventBuilder` and every other caller of `Timestamp::now` need
  `universal_time::define_time_provider!` in the consumer's binary. This crate defines no time
  provider, so it cannot collide with yours, and it builds events with `UnsignedEvent::new` and
  `js_sys::Date::now()` instead. With rustc 1.99.0 and 1.99.1, a wasm binary that reaches `Timestamp::now`
  without a provider fails at link time (`a time provider is required`). Other toolchains may
  behave the other way: a missing provider could link and then trap at runtime with no build
  warning. Do not assume `EventBuilder` works on wasm without a provider. This includes
  `EventBuilder::finalize_async` and `nostr` helpers that build through it, and
  `custom_created_at` did not avoid the link error with rustc 1.99.1, in a dev build or with
  `opt-level = "z"` and `lto`.
- **Breaking:** A NIP-46 `auth_url` no longer returns an error containing the URL. The request stays pending and
  a mounted modal shows the link. Direct `BunkerSession` callers mount one closed modal, for example
  `<NostrAuthModal open=false on_auth=... />`; a provider already mounts its own. With no modal
  mounted the request fails at its timeout with the new `NostrAuthError::BunkerAuthRequired`.
- **Breaking:** `bunker://` errors changed: everything `nostr`'s URI parser rejects, including a bad or missing
  pubkey, and an off-curve pubkey it accepts, is now `InvalidBunkerUri("invalid URI")`. A bad pubkey was `InvalidPublicKey`.
- **Breaking:** A persisted relay URL that `nostr`'s `RelayUrl` rejects (not `ws`/`wss`, or a second `://`) now
  fails restore, and the session is kept like any other failed restore.
- **Breaking:** A `bunker://` URI may list at most five relays after duplicates are removed. More are refused.
- **Breaking:** `Nip07Handle::nip44_*` and `BunkerSession::nip44_*` now take `peer: &PublicKey`, not a hex string.
  A peer that is not on the curve is `InvalidPublicKey` on every method, before anything is sent.
  Before, an extension was handed whatever it was given, and a bunker path only checked the hex.
- **Breaking:** A signer's refusal of `sign_event` is now `SigningFailed(text)`, and of `nip44_encrypt` or
  `nip44_decrypt` is `EncryptionFailed(text)`, not `BunkerConnectionFailed(text)`. A refusal at login
  stays `BunkerConnectionFailed`.
- **Breaking:** Logging out, or a login or restore replacing a session, closes that bunker session for good, even
  when the new login is the same identity. Pending requests and later calls on any clone, including
  one kept in your own state, fail with the new `NostrAuthError::BunkerSessionClosed` and never
  reconnect; before, a kept clone reconnected. Retrying cannot succeed. Read the current session from
  `NostrAuthContext::auth` instead of keeping a signer across login changes. A failed login closes
  nothing. `to_persisted_session` and the public fields still read.
- **Breaking:** Events returned by an extension or a bunker are now checked. Another key is the new
  `NostrAuthError::SignerKeyMismatch`. A changed `kind`, `tags`, `content` or `created_at`, a wrong
  id or a bad signature is `SigningFailed`, so an extension that rewrites a field now fails every
  signature. Before, all of these returned `Ok`.
- **Breaking:** A request whose `pubkey` differs from the session, or whose preset `id` does not match its fields,
  is now `SigningFailed("event pubkey differs from the session key")` or
  `SigningFailed("event id does not match its fields")` on every method, and a remote signer never
  sees it. Before, a remote signer could return `Ok`, and local keys failed with `nostr`'s text.
- **Breaking:** Extension requests now go through the same parsing as other methods. Malformed JSON is
  `Serialization`, not `SigningFailed("invalid event JSON: ..")`. A missing field, `id:""`,
  `pubkey:null`, a non-string tag element, an empty tag, a `kind` above 65535 or a non-integer
  `created_at` is `Serialization` with nothing sent. Unknown request fields are dropped.
- **Breaking:** A direct `Nip07Handle::sign_event` no longer returns `Ok("")`, `Ok("null")` or an object missing a
  field, including `{"sig":..}`. All are `SigningFailed("signer returned an invalid event")`.
- **Breaking:** `PasskeySession::authenticate` now takes `rp_id` first: `authenticate(rp_id, credential_id)`. It always sends `rpId`.
- **Breaking:** `rpId` is now always sent, so changing `rp_id` strands credentials made under the old value, including ones made under the hostname before `rp_id` was set. Reverting the config recovers them.
- **Breaking:** `ReadOnlyHandle::from_str` and the read-only step now reject off-curve hex, `npub` and `nprofile`, with new error text. About half of all hex secret keys are also valid public keys. Those are still accepted, shown and persisted as a public key.
- **Breaking:** `NostrAuthModal`'s `on_auth` and `on_close` now accept closures, as in `on_auth=move |result: AuthResult| ...`. A closure passed this way must be `Send + Sync + 'static`, like one given to `Callback::new`. `Callback::new(|x| ...)` or `Callback::new(|_| ...)` on these props no longer infers its parameter type, so write it: `|x: AuthResult|` or `|_: AuthResult|` on `on_auth`, and `|(): ()|` on `on_close`. `Callback` values and annotated closures need no change.
- A bunker `sign_event` result now uses `nostr`'s JSON key order, not the order the signer sent.
- A raw `+` in a URI secret now decodes to a space. Hex and UUID secrets are unaffected.
- A lost relay socket now fails pending requests with `BunkerConnectionFailed("relay connection lost")` as soon as the browser reports the close, including requests waiting for approval, which need a retry. A relay's close frame with TCP held open can wait for the browser's grace period or a new request, bounded by the request's deadline.
- A pending request can fail with that same error once another request on the socket has timed out
  and a new request arrives, because the new request reconnects. A request waiting on a verified
  approval link keeps the socket instead.
- A call waiting on another call's reconnect gets `BunkerConnectionFailed("reconnect cancelled")` if
  that call's future is dropped.
- A malformed return through the trait is now `SigningFailed("signer returned an invalid event")`,
  without the parser's text.
- Local keys now fill in an absent `pubkey`, where they returned `Serialization`. Duplicate JSON keys
  in a local request now take the last value, where they were a serde error.
- A `Nip07Handle::sign_event` result now uses `nostr`'s JSON key order, with extra fields removed.
- An extension that rejects with a non-Error object now gives the static text "extension rejected the
  request", not a dump of the object.
- A stored session of any method is now kept when restore fails for any reason, including another
  key and data that can never restore. The user is logged out, `is_restoring` ends false, and restore
  is retried on next load, or for a passkey on the next login click. Before, most failures deleted it, and an absent or throwing extension left
  `is_restoring` stuck true. An extension that asks on every call now prompts on every load until the
  user forgets the session.
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
- `create` no longer filters on `authenticatorAttachment`, so security keys and cross-device passkeys are offered. An authenticator without PRF reaches `create`, gets `PasskeyNotSupported` and leaves a credential behind on each retry. The variant's text is now "This browser or authenticator does not support the WebAuthn PRF extension".
- `create` now completes through a follow-up `get` when the authenticator reports `prf.enabled` with no output. If that fails, the error says to use the existing passkey.
- The passkey option is hidden when `PublicKeyCredential` is absent, or `getClientCapabilities()` reports `extension:prf` as false. An unknown capability keeps it.
- The modal always reopens on its method list, including after a login with a modal you keep open.
- Close, Escape, backdrop, Back, a parent closing `open`, and unmount cancel a login. A late approval or failure never reaches `on_auth` or the error line. A login's approval link clears when it is cancelled. A cancelled bunker login may have spent its one-time secret, so a retry can need a new URI.
- `logout` also closes the provider's modal and cancels a login in it, discarding typed input. `logout` then `show_login` reopens on the list.
- A session removal in another tab cancels a login running in this tab's modal and closes it, with no reason shown. With no login running the modal stays open with what was typed, and submitting it is a new login.
- A restore landing closes the provider's modal only on its method list. On a login step it stays open. A modal you mount yourself is not affected.
- The extension is re-detected each time the modal opens.
- Dropping the future of `PasskeySession::create` or `authenticate` now aborts the browser prompt, where the browser honours it. Keep polling it, or spawn it, to keep the prompt up.
- The Apple passkey subtitle no longer claims iCloud sync.
- A stored session with an off-curve key no longer restores. `restore_error` is `InvalidPublicKey` and the session is kept under the session rule, so it stays in localStorage until logout or a new login.
- An extension returning a string from `getPublicKey` that is off-curve or unparseable now gets `InvalidPublicKey("the extension returned an invalid public key")` at login, from `nip44_*` and on restore. A non-string stays `ExtensionRejected("expected string pubkey")`. On `nip44_*` and restore an off-curve key was `SignerKeyMismatch`, so an app prompting for an account switch on that variant will not prompt here. `nip44` is not called. The session is kept, and restores once the extension returns the stored key. `sign_event` is unchanged, and still reports `SignerKeyMismatch` for that account after any prompt from the extension. `InvalidPublicKey` in `restore_error` is therefore not proof that a session is dead: do not offer to forget it on the variant alone.
- ncryptsec decrypt now starts after two frames, or a 200 ms timer that browsers may throttle in a background tab; best effort, no paint is guaranteed. It started after a 16 ms timer before. scrypt still blocks the main thread.

### Added

- `AuthResult` now implements `nostr`'s `AsyncGetPublicKey`, `AsyncSignEvent` and `Debug`. `Debug`
  prints the variant and public key only.
- `AuthResult` now has `nip44_encrypt` and `nip44_decrypt`, async, on every login method, and
  implements `AsyncNip44`. `PasskeySession` and `RawKeySession` gain sync `nip44_*`. New
  `NostrAuthError::EncryptionUnavailable`, for a read-only session and for an extension or bunker
  session on a server, where the stubs returned `SigningFailed`, and `NostrAuthError::EncryptionFailed`.
- New `NostrAuthContext::has_saved_session` and `restore_error`, and new
  `NostrAuthError::RestoreMethodNotAllowed`. A stored session whose method left `allowed_methods` no
  longer restores or prompts. A mismatch on restore reports `SignerKeyMismatch` for every method.
  A signer returning no valid key is not a mismatch: an extension returning a malformed or off-curve key string reports `InvalidPublicKey`, where an off-curve one reported `SignerKeyMismatch` before.
- The read-only step has a new warning box on the `data-nostr-warning` hook, ending "Anything rejected is cleared from this field."
- The bunker step has a new one-time-secret hint on the `data-nostr-tip` hook, on every platform, so CSS for that hook now applies off Android too.
- The ncryptsec step has a new sentence: "A value no password can open is cleared from this field."

### Removed

- **Breaking:** The Amber method button and its `data-nostr-icon-amber` hook are gone; use Nostr Connect. The Android tip stays in that step.
- **Breaking:** The built-in restore indicator and its `[data-nostr-restoring]` hook are gone. Render your own from `is_restoring`.

### Fixed

- A missing `window.nostr`, `nip44` or method, or a non-callable one, is now always
  `ExtensionNotFound`, including from `Nip07Handle::get_public_key`. Before, it raised an uncaught
  `TypeError` and the future never finished.
- A present extension method that throws synchronously is now a rejection, the same as an asynchronous
  one: `SigningFailed(msg)` for `signEvent`, `EncryptionFailed(msg)` for `nip44_*`,
  `ExtensionRejected(msg)` for `getPublicKey`.
  Before, it raised an uncaught `TypeError` and the future never finished.
- A login or logout now cancels a restore in flight, and its result is discarded. Before, a late
  result could log a user back in or delete a session a login had just saved.
- A login with a method that cannot persist, as a different identity, now clears the stored session,
  so a reload no longer returns the old identity. So does a login whose write fails.
- A passkey created under a configured `rp_id` now logs in on a subdomain. A site with no configured `rp_id` sees no change. Every host that can use the RP ID can derive the key, so keep the hostname default unless you trust every such host.
- Escape with a modal closed no longer fires `on_close`.
- A bunker socket is no longer torn down after an approval link expires or the signer sends an unusable
  answer, which failed other pending requests as "relay connection lost". A request failed because the
  crate replaced its socket now says the signer may still have received it, so apps do not blindly
  retry a signature.

### Security

- `PersistedSession`'s `Debug` now prints `bunker_uri` and `bunker_client_secret_hex` as `<redacted>`. Serde output is unchanged.
- The secret key and read-only inputs now empty on every submit, and the password input on every submit except one refused for an empty `ncryptsec` field. A mistyped `npub` or `nprofile` must be pasted again. Emptying wipes the signal's buffer only: the DOM value, `event.target.value`, earlier keystrokes' strings and `prop:value` clones remain until collected, and a script on the page could already have read the paste. A secret pasted in the read-only field should be treated as exposed. See [What is wiped](https://github.com/Sturnine/leptos-nostr-auth#what-is-wiped-and-what-is-not).
- A bunker URI stays after a failed login, as it did before, in clear text with any secret, until the user leaves the step, including under a restore landing on that step or a removal in another tab with no login running. Retrying a URI whose secret was spent fails with the signer's text and needs a new URI. Whether a signer spends a secret on a failed attempt is unknown. What changed: `InvalidBunkerUri` now empties the field, so a typo there is gone. A secret pasted in this field should be treated as exposed.
- An `ncryptsec` string now stays only after `WrongPassword`, where anyone who reads it can attack it offline at its scrypt cost. `InvalidNcryptsec`, including a pasted `nsec1...` and the `log_n` refusal, empties the field, and the error says why. A secret pasted in this field should be treated as exposed.
- The bunker, ncryptsec, password, secret key and read-only inputs now carry `autocomplete="off"` and `spellcheck="false"`. Browsers may ignore `autocomplete="off"`.
- Documented that every origin allowed to use the passkey RP ID can derive the user's Nostr key, that the hostname default is the safe choice, and that a passkey identity has no backup. The examples no longer set `rp_id`.
- Documented that a bunker restore's matching public key does not prove the signer holds the key, and that a one-time localStorage write can redirect a stored bunker session, or swap in another identity, until logout.
- A bunker session now encrypts or decrypts only after its signer has produced a valid signature for the account. If the app has not signed yet, the first NIP-44 call sends one signing request for an unpublished check event, which some signers ask the user to approve. A stored session pointed at another signer can no longer receive NIP-44 plaintext.
- Extension error text is now sanitized and capped like bunker text, and both now also drop line separators, the Arabic letter mark, interlinear annotation and tag characters, and blank Hangul fillers.

## [0.1.0] - 2026-07-22

Initial release.

[Unreleased]: https://github.com/Sturnine/leptos-nostr-auth/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Sturnine/leptos-nostr-auth/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Sturnine/leptos-nostr-auth/releases/tag/v0.1.0
