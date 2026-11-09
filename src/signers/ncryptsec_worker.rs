use super::raw_key::RawKeySession;
use crate::types::NostrAuthError;

impl RawKeySession {
    /// Decrypt a NIP-49 `ncryptsec1...` string in a dedicated web worker, so scrypt does not freeze
    /// the page and its memory is freed with the worker.
    ///
    /// Without a URL, or when the worker cannot start, this decrypts on the main thread like
    /// [`RawKeySession::from_ncryptsec`], after yielding for a paint. Once the request is sent
    /// there is no fallback. Dropping the future terminates the worker.
    ///
    /// # Errors
    ///
    /// The same errors as [`RawKeySession::from_ncryptsec`], plus
    /// [`NostrAuthError::NcryptsecDecryptAborted`].
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the modal does not call it yet")
    )]
    pub(crate) async fn from_ncryptsec_off_thread(
        ncryptsec: &str,
        password: &str,
        worker_url: Option<&str>,
    ) -> Result<Self, NostrAuthError> {
        imp::from_ncryptsec_off_thread(ncryptsec, password, worker_url).await
    }
}

/// Run the ncryptsec worker. Call it once, from the worker bin's `main` (Trunk) or after `init(...)`
/// in a module worker (cargo-leptos, through the JS name `leptosNostrAuthNcryptsecWorker`).
///
/// It does nothing outside a dedicated worker, and nothing under `ssr`.
#[cfg_attr(
    feature = "hydrate",
    wasm_bindgen::prelude::wasm_bindgen(js_name = "leptosNostrAuthNcryptsecWorker")
)]
#[cfg_attr(
    feature = "ssr",
    expect(clippy::missing_const_for_fn, reason = "only the server stub is const")
)]
pub fn run_ncryptsec_worker() {
    imp::run_worker();
}

#[cfg(not(feature = "ssr"))]
mod imp {
    use core::cell::{Cell, RefCell};
    use core::fmt;
    use std::rc::Rc;

    use js_sys::{Array, Promise, Uint8Array};
    use nostr::key::SecretKey;
    use wasm_bindgen::prelude::*;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{DedicatedWorkerGlobalScope, MessageEvent, Worker, WorkerOptions, WorkerType};
    use zeroize::Zeroizing;

    use crate::signers::browser::{RpcTimer, make_rpc_promise};
    use crate::signers::raw_key::{RawKeySession, decrypt_payload, parse_ncryptsec};
    use crate::signers::sanitize_remote_text;
    use crate::types::NostrAuthError;

    const VERSION: u32 = 1;
    const READY: &str = "leptos-nostr-auth/ncryptsec-worker";
    const READY_TIMEOUT_SECS: u32 = 10;
    const KEY_LEN: u32 = 32;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Status {
        Key,
        WrongPassword,
        Invalid,
    }

    impl Status {
        const fn tag(self) -> &'static str {
            match self {
                Self::Key => "key",
                Self::WrongPassword => "wrong-password",
                Self::Invalid => "invalid",
            }
        }

        fn from_tag(tag: &str) -> Option<Self> {
            [Self::Key, Self::WrongPassword, Self::Invalid]
                .into_iter()
                .find(|status| status.tag() == tag)
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum ReplyCheck {
        Key,
        WrongPassword,
        Invalid(String),
        Malformed,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FallbackCause {
        NoUrl,
        ConstructorThrew,
        LoadError,
        ReadyTimeout,
        VersionMismatch,
    }

    impl FallbackCause {
        /// Apps without a worker fall back silently.
        const fn warns(self) -> bool {
            !matches!(self, Self::NoUrl)
        }
    }

    impl fmt::Display for FallbackCause {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::NoUrl => f.write_str("no worker URL is configured"),
                Self::ConstructorThrew => f.write_str("the Worker constructor threw"),
                Self::LoadError => f.write_str("the worker failed to load"),
                Self::ReadyTimeout => {
                    write!(f, "the worker was not ready within {READY_TIMEOUT_SECS} s")
                }
                Self::VersionMismatch => f.write_str(
                    "the worker speaks another protocol version, possibly a stale cached file",
                ),
            }
        }
    }

    /// Only a stale or foreign script can send anything but the current ready message.
    fn check_ready(tag: Option<&str>, version_matches: bool) -> Result<(), FallbackCause> {
        if tag == Some(READY) && version_matches {
            Ok(())
        } else {
            Err(FallbackCause::VersionMismatch)
        }
    }

    fn check_reply(status: Option<&str>, key_len: Option<u32>, text: Option<String>) -> ReplyCheck {
        match status.and_then(Status::from_tag) {
            Some(Status::Key) if key_len == Some(KEY_LEN) => ReplyCheck::Key,
            Some(Status::WrongPassword) => ReplyCheck::WrongPassword,
            Some(Status::Invalid) => text.map_or(ReplyCheck::Malformed, |text| {
                ReplyCheck::Invalid(sanitize_remote_text(&text))
            }),
            _ => ReplyCheck::Malformed,
        }
    }

    /// `decrypt_payload` returns only `WrongPassword` and `InvalidNcryptsec`.
    fn reply_status(error: &NostrAuthError) -> (Status, Option<String>) {
        match error {
            NostrAuthError::WrongPassword => (Status::WrongPassword, None),
            NostrAuthError::InvalidNcryptsec(text) => (Status::Invalid, Some(text.clone())),
            other => (Status::Invalid, Some(other.to_string())),
        }
    }

    fn read_ready(data: &JsValue) -> Result<(), FallbackCause> {
        if !Array::is_array(data) {
            return Err(FallbackCause::VersionMismatch);
        }
        let data: &Array = data.unchecked_ref();
        check_ready(data.get(0).as_string().as_deref(), data.get(1) == VERSION)
    }

    fn read_reply(data: &JsValue) -> Result<SecretKey, NostrAuthError> {
        if !Array::is_array(data) {
            return Err(NostrAuthError::NcryptsecDecryptAborted);
        }
        let data: &Array = data.unchecked_ref();
        let status = data.get(0).as_string();
        let body_value = data.get(1);
        let body = body_value.dyn_ref::<Uint8Array>();
        let mut key = Zeroizing::new([0_u8; 32]);
        let body_len = body.map(|body| {
            let len = body.length();
            if len == KEY_LEN {
                body.copy_to(key.as_mut_slice());
            }
            body.fill(0, 0, len);
            len
        });
        match check_reply(status.as_deref(), body_len, body_value.as_string()) {
            ReplyCheck::Key => SecretKey::from_slice(key.as_slice())
                .ok()
                .ok_or(NostrAuthError::NcryptsecDecryptAborted),
            ReplyCheck::WrongPassword => Err(NostrAuthError::WrongPassword),
            ReplyCheck::Invalid(text) => Err(NostrAuthError::InvalidNcryptsec(text)),
            ReplyCheck::Malformed => Err(NostrAuthError::NcryptsecDecryptAborted),
        }
    }

    enum WorkerEvent {
        Message(JsValue),
        Error,
    }

    #[derive(Default)]
    struct Inbox {
        event: Option<WorkerEvent>,
        wake: Option<js_sys::Function>,
    }

    #[expect(dead_code, reason = "held to keep the closures alive, never read")]
    struct Handlers {
        message: Closure<dyn FnMut(MessageEvent)>,
        error: Closure<dyn FnMut(web_sys::Event)>,
        message_error: Closure<dyn FnMut(MessageEvent)>,
    }

    /// Dropping it terminates the worker, which frees all its memory, scrypt scratch included.
    struct WorkerGuard {
        worker: Worker,
        inbox: Rc<RefCell<Inbox>>,
        _handlers: Handlers,
    }

    fn deliver(inbox: &RefCell<Inbox>, event: WorkerEvent) {
        let wake = {
            let mut inbox = inbox.borrow_mut();
            if inbox.event.is_none() {
                inbox.event = Some(event);
            }
            inbox.wake.take()
        };
        if let Some(wake) = wake {
            let _ = wake.call0(&JsValue::UNDEFINED);
        }
    }

    impl WorkerGuard {
        fn new(worker: Worker) -> Self {
            let inbox = Rc::new(RefCell::new(Inbox::default()));
            let on_message = {
                let inbox = Rc::clone(&inbox);
                Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
                    deliver(&inbox, WorkerEvent::Message(event.data()));
                })
            };
            let on_error = {
                let inbox = Rc::clone(&inbox);
                Closure::<dyn FnMut(web_sys::Event)>::new(move |_| {
                    deliver(&inbox, WorkerEvent::Error);
                })
            };
            // A reply that cannot be deserialized fires only this event, and the reply wait has no timer.
            let on_message_error = {
                let inbox = Rc::clone(&inbox);
                Closure::<dyn FnMut(MessageEvent)>::new(move |_| {
                    deliver(&inbox, WorkerEvent::Error);
                })
            };
            worker.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
            worker.set_onerror(Some(on_error.as_ref().unchecked_ref()));
            worker.set_onmessageerror(Some(on_message_error.as_ref().unchecked_ref()));
            Self {
                worker,
                inbox,
                _handlers: Handlers {
                    message: on_message,
                    error: on_error,
                    message_error: on_message_error,
                },
            }
        }

        /// `None` means the timer fired.
        async fn next(&self, timeout: Option<u32>) -> Option<WorkerEvent> {
            // Safe because the ready-phase future runs on through the post and into `next(None)`
            // within one microtask checkpoint, so no worker event can slip in between.
            self.inbox.borrow_mut().event = None;
            let (woken, resolve, _) = make_rpc_promise();
            self.inbox.borrow_mut().wake = Some(resolve);
            if let Some(secs) = timeout {
                let timer = RpcTimer::start(secs);
                let race = Promise::race(&Array::of2(&woken, timer.fired()));
                let _ = JsFuture::from(race).await;
            } else {
                let _ = JsFuture::from(woken).await;
            }
            self.inbox.borrow_mut().event.take()
        }
    }

    impl Drop for WorkerGuard {
        fn drop(&mut self) {
            self.worker.set_onmessage(None);
            self.worker.set_onerror(None);
            self.worker.set_onmessageerror(None);
            self.worker.terminate();
            let wake = self.inbox.borrow_mut().wake.take();
            if let Some(wake) = wake {
                // `JsFuture` frees its callbacks only when its promise settles, and the reply wait
                // has no timer to settle it, so a cancelled future would leak them.
                let _ = wake.call0(&JsValue::UNDEFINED);
            }
        }
    }

    thread_local! {
        static WARNED: Cell<bool> = const { Cell::new(false) };
    }

    fn warn_once(cause: FallbackCause) {
        if !WARNED.replace(true) {
            web_sys::console::warn_1(
                &format!("leptos-nostr-auth: decrypting the ncryptsec on the main thread: {cause}")
                    .into(),
            );
        }
    }

    /// Give the browser a chance to paint before scrypt blocks the thread: two frames, or a 200 ms timer
    /// that browsers may throttle in a background tab. Best effort, no paint is guaranteed. A frame
    /// slower than the timer also starts scrypt before the paint.
    async fn yield_for_paint() {
        // rAF never fires in a hidden tab, so a backgrounded login would otherwise stall until refocus.
        const PAINT_WAIT_MS: i32 = 200;
        let Some(window) = web_sys::window() else {
            return;
        };
        let promise = js_sys::Promise::new(&mut |resolve, _| {
            let second_frame = {
                let resolve = resolve.clone();
                Closure::once_into_js(move || {
                    let _ = resolve.call0(&JsValue::UNDEFINED);
                })
            };
            let first_frame = {
                let window = window.clone();
                Closure::once_into_js(move || {
                    let _ = window.request_animation_frame(second_frame.unchecked_ref());
                })
            };
            let _ = window.request_animation_frame(first_frame.unchecked_ref());
            let _ = window
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, PAINT_WAIT_MS);
        });
        let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
    }

    async fn fallback(
        cause: FallbackCause,
        ncryptsec: &str,
        password: &str,
    ) -> Result<RawKeySession, NostrAuthError> {
        if cause.warns() {
            warn_once(cause);
        }
        yield_for_paint().await;
        RawKeySession::from_ncryptsec(ncryptsec, password)
    }

    fn spawn(url: &str) -> Option<Worker> {
        let options = WorkerOptions::new();
        options.set_type(WorkerType::Module);
        Worker::new_with_options(url, &options).ok()
    }

    pub(super) async fn from_ncryptsec_off_thread(
        ncryptsec: &str,
        password: &str,
        worker_url: Option<&str>,
    ) -> Result<RawKeySession, NostrAuthError> {
        let encrypted = parse_ncryptsec(ncryptsec)?;
        let Some(url) = worker_url else {
            return fallback(FallbackCause::NoUrl, ncryptsec, password).await;
        };
        // Before `RpcTimer::start`, which unwraps `window`: under Node `new Worker` throws.
        let Some(worker) = spawn(url) else {
            return fallback(FallbackCause::ConstructorThrew, ncryptsec, password).await;
        };
        let guard = WorkerGuard::new(worker);
        let ready = match guard.next(Some(READY_TIMEOUT_SECS)).await {
            None => Err(FallbackCause::ReadyTimeout),
            Some(WorkerEvent::Error) => Err(FallbackCause::LoadError),
            Some(WorkerEvent::Message(data)) => read_ready(&data),
        };
        if let Err(cause) = ready {
            drop(guard);
            return fallback(cause, ncryptsec, password).await;
        }

        let payload = Uint8Array::from(encrypted.as_vec().as_slice());
        let password_bytes = Uint8Array::from(password.as_bytes());
        let posted = guard.worker.post_message_with_transfer(
            &Array::of2(&payload, &password_bytes),
            &Array::of2(&payload.buffer(), &password_bytes.buffer()),
        );
        if posted.is_err() {
            payload.fill(0, 0, payload.length());
            password_bytes.fill(0, 0, password_bytes.length());
            return Err(NostrAuthError::NcryptsecDecryptAborted);
        }

        let secret_key = match guard.next(None).await {
            Some(WorkerEvent::Message(data)) => read_reply(&data)?,
            _ => return Err(NostrAuthError::NcryptsecDecryptAborted),
        };
        Ok(RawKeySession::from_secret_key(secret_key))
    }

    pub(super) fn run_worker() {
        let Ok(scope) = js_sys::global().dyn_into::<DedicatedWorkerGlobalScope>() else {
            return;
        };
        let reply_scope = scope.clone();
        let on_request = Closure::<dyn FnMut(MessageEvent)>::new(move |event: MessageEvent| {
            let reply = handle_request(&event.data());
            if let Ok(key) = reply.get(1).dyn_into::<Uint8Array>() {
                let transfer = Array::of1(&key.buffer());
                if reply_scope
                    .post_message_with_transfer(&reply, &transfer)
                    .is_err()
                {
                    key.fill(0, 0, key.length());
                }
            } else {
                let _ = reply_scope.post_message(&reply);
            }
        });
        scope.set_onmessage(Some(on_request.as_ref().unchecked_ref()));
        // The worker serves a single decrypt and is then terminated, so the handler is never freed.
        let _ = on_request.into_js_value();
        let _ = scope.post_message(&Array::of2(&READY.into(), &VERSION.into()));
    }

    fn handle_request(request: &JsValue) -> Array {
        let items = request.dyn_ref::<Array>();
        let take = |index: u32| -> Zeroizing<Vec<u8>> {
            let view = items.and_then(|items| items.get(index).dyn_into::<Uint8Array>().ok());
            view.map_or_else(
                || Zeroizing::new(Vec::new()),
                |view| {
                    let bytes = Zeroizing::new(view.to_vec());
                    view.fill(0, 0, view.length());
                    bytes
                },
            )
        };
        let payload = take(0);
        let password = take(1);
        let password = core::str::from_utf8(&password).unwrap_or("");
        match decrypt_payload(&payload, password) {
            // Not `to_secret_bytes`, which leaves an unwiped copy. Dropping the key erases ours.
            Ok(key) => Array::of2(
                &Status::Key.tag().into(),
                &Uint8Array::from(key.as_secret_bytes()),
            ),
            Err(error) => {
                let (status, text) = reply_status(&error);
                text.map_or_else(
                    || Array::of1(&status.tag().into()),
                    |text| Array::of2(&status.tag().into(), &text.into()),
                )
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn status_tags_round_trip() {
            for status in [Status::Key, Status::WrongPassword, Status::Invalid] {
                assert_eq!(Status::from_tag(status.tag()), Some(status));
            }
            for error in [
                NostrAuthError::WrongPassword,
                NostrAuthError::InvalidNcryptsec("x".to_owned()),
            ] {
                let (status, text) = reply_status(&error);
                let expected = match &error {
                    NostrAuthError::WrongPassword => ReplyCheck::WrongPassword,
                    _ => ReplyCheck::Invalid("x".to_owned()),
                };
                assert_eq!(check_reply(Some(status.tag()), None, text), expected);
            }
        }

        #[test]
        fn version_mismatch_falls_back() {
            for (tag, matches) in [(Some(READY), false), (Some("other"), true), (None, false)] {
                assert_eq!(
                    check_ready(tag, matches),
                    Err(FallbackCause::VersionMismatch)
                );
            }
            assert_eq!(check_ready(Some(READY), true), Ok(()));
        }

        #[test]
        fn malformed_reply_aborts() {
            let key = Some("key");
            for (status, len, text) in [
                (key, Some(31), None),
                (key, None, None),
                (Some("invalid"), None, None),
                (Some("bogus"), Some(32), Some("t".to_owned())),
                (None, Some(32), None),
            ] {
                assert_eq!(check_reply(status, len, text), ReplyCheck::Malformed);
            }
            assert_eq!(check_reply(key, Some(32), None), ReplyCheck::Key);
        }

        #[test]
        fn no_url_is_silent() {
            assert!(!FallbackCause::NoUrl.warns());
            for cause in [
                FallbackCause::ConstructorThrew,
                FallbackCause::LoadError,
                FallbackCause::ReadyTimeout,
                FallbackCause::VersionMismatch,
            ] {
                assert!(cause.warns());
            }
            assert!(FallbackCause::ReadyTimeout.to_string().contains("10 s"));
        }
    }

    #[cfg(all(test, target_arch = "wasm32"))]
    #[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
    mod wasm_tests {
        use super::*;
        use crate::signers::ncryptsec_worker::tests::{
            CRYPTSEC, CRYPTSEC_PUBKEY, cheap_key, cheap_key_bech32, cheap_pubkey, over_cap_key,
        };
        use js_sys::Reflect;
        use nostr::nips::nip19::FromBech32 as _;
        use wasm_bindgen_test::wasm_bindgen_test;

        fn zeroed(array: &Uint8Array) -> bool {
            array.to_vec().iter().all(|byte| *byte == 0)
        }

        fn eval(code: &str) -> JsValue {
            js_sys::eval(code).unwrap()
        }

        #[wasm_bindgen_test]
        fn handler_returns_spec_key_and_wipes_inputs() {
            let bytes = nostr::nips::nip49::EncryptedSecretKey::from_bech32(CRYPTSEC)
                .unwrap()
                .as_vec();
            let p = Uint8Array::from(bytes.as_slice());
            let w = Uint8Array::from(&b"nostr"[..]);
            let key = read_reply(&handle_request(&Array::of2(&p, &w))).unwrap();
            let session = RawKeySession::from_secret_key(key);
            assert_eq!(session.public_key.to_hex(), CRYPTSEC_PUBKEY);
            assert!(zeroed(&p) && zeroed(&w));
        }

        #[wasm_bindgen_test]
        fn handler_wrong_password() {
            let p = Uint8Array::from(cheap_key().as_slice());
            let w = Uint8Array::from(&b"wrong"[..]);
            let reply = handle_request(&Array::of2(&p, &w));
            assert!(matches!(
                read_reply(&reply),
                Err(NostrAuthError::WrongPassword)
            ));
        }

        #[wasm_bindgen_test]
        fn read_reply_maps_malformed_and_wipes() {
            let short = eval("[\"key\", new Uint8Array(31).fill(7)]");
            assert!(matches!(
                read_reply(&short),
                Err(NostrAuthError::NcryptsecDecryptAborted)
            ));
            let body = Reflect::get_u32(&short, 1).unwrap();
            assert!(zeroed(&body.unchecked_into()));
            for code in ["[\"invalid\", 5]", "\"x\"", "[\"bogus\"]"] {
                assert!(matches!(
                    read_reply(&eval(code)),
                    Err(NostrAuthError::NcryptsecDecryptAborted)
                ));
            }
            assert_eq!(
                read_ready(&eval(&format!("[\"{READY}\", 2]"))),
                Err(FallbackCause::VersionMismatch)
            );
            assert_eq!(
                read_ready(&eval("[\"other\", 1]")),
                Err(FallbackCause::VersionMismatch)
            );
            assert_eq!(read_ready(&eval(&format!("[\"{READY}\", 1]"))), Ok(()));
        }

        #[wasm_bindgen_test]
        async fn falls_back_without_worker() {
            assert!(!Reflect::has(&js_sys::global(), &"Worker".into()).unwrap());
            let session = from_ncryptsec_off_thread(
                &cheap_key_bech32(),
                "pw",
                Some("/nostr-auth-worker_loader.js"),
            )
            .await
            .unwrap();
            assert_eq!(session.public_key.to_hex(), cheap_pubkey());
        }

        #[wasm_bindgen_test]
        async fn constructor_throw_falls_back_after_cap_check() {
            eval(
                "globalThis.__nw = 0; globalThis.Worker = function () { globalThis.__nw++; throw new Error('no'); }",
            );
            let over = from_ncryptsec_off_thread(&over_cap_key(), "pw", Some("/w.js")).await;
            let after_over = eval("globalThis.__nw").as_f64();
            let cheap = from_ncryptsec_off_thread(&cheap_key_bech32(), "pw", Some("/w.js")).await;
            let after_cheap = eval("globalThis.__nw").as_f64();
            eval("delete globalThis.Worker; delete globalThis.__nw");
            assert!(matches!(over, Err(NostrAuthError::InvalidNcryptsec(_))));
            assert_eq!(after_over, Some(0.0));
            assert_eq!(cheap.unwrap().public_key.to_hex(), cheap_pubkey());
            assert_eq!(after_cheap, Some(1.0));
        }

        #[wasm_bindgen_test]
        fn run_worker_outside_worker_is_noop() {
            super::super::super::run_ncryptsec_worker();
        }
    }
}

#[cfg(feature = "ssr")]
mod imp {
    use crate::signers::raw_key::RawKeySession;
    use crate::types::NostrAuthError;

    pub(super) async fn from_ncryptsec_off_thread(
        ncryptsec: &str,
        password: &str,
        _worker_url: Option<&str>,
    ) -> Result<RawKeySession, NostrAuthError> {
        RawKeySession::from_ncryptsec(ncryptsec, password)
    }

    pub(super) const fn run_worker() {}
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod tests {
    use super::*;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use nostr::key::SecretKey;
    use nostr::nips::nip19::ToBech32 as _;
    use nostr::nips::nip49::{EncryptedSecretKey, KeySecurity};

    #[cfg(any(feature = "ssr", target_arch = "wasm32"))]
    pub(super) const CRYPTSEC: &str = "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p";
    #[cfg(any(feature = "ssr", target_arch = "wasm32"))]
    pub(super) const CRYPTSEC_PUBKEY: &str =
        "672a31bfc59d3f04548ec9b7daeeba2f61814e8ccc40448045007f5479f693a3";

    fn cheap_secret() -> SecretKey {
        SecretKey::from_hex(&"11".repeat(32)).unwrap()
    }

    pub(super) fn cheap_key() -> Vec<u8> {
        EncryptedSecretKey::new(&cheap_secret(), "pw", 4, KeySecurity::Unknown)
            .unwrap()
            .as_vec()
    }

    #[cfg(target_arch = "wasm32")]
    pub(super) fn cheap_key_bech32() -> String {
        EncryptedSecretKey::from_slice(&cheap_key())
            .unwrap()
            .to_bech32()
            .unwrap()
    }

    #[cfg(target_arch = "wasm32")]
    pub(super) fn cheap_pubkey() -> String {
        nostr::key::Keys::new(cheap_secret()).public_key().to_hex()
    }

    pub(super) fn over_cap_key() -> String {
        let mut bytes = cheap_key();
        *bytes.get_mut(1).unwrap() = EncryptedSecretKey::MAX_LOG_N + 1;
        EncryptedSecretKey::from_slice(&bytes)
            .unwrap()
            .to_bech32()
            .unwrap()
    }

    fn poll_once<F: Future>(fut: F) -> Poll<F::Output> {
        pin!(fut).poll(&mut Context::from_waker(Waker::noop()))
    }

    #[test]
    fn cap_checked_before_any_worker() {
        for key in [over_cap_key().as_str(), "not-an-ncryptsec"] {
            let polled = poll_once(RawKeySession::from_ncryptsec_off_thread(
                key,
                "nostr",
                Some("/w.js"),
            ));
            assert!(matches!(
                polled,
                Poll::Ready(Err(NostrAuthError::InvalidNcryptsec(_)))
            ));
        }
    }

    #[test]
    fn aborted_error_text() {
        assert_eq!(
            NostrAuthError::NcryptsecDecryptAborted.to_string(),
            "Decrypting stopped before it finished, most likely for lack of memory. Close other tabs and try again, or use another login method."
        );
    }

    #[cfg(feature = "ssr")]
    #[test]
    fn server_decrypts_synchronously() {
        use crate::signers::server_tests::ready;
        let session = ready(RawKeySession::from_ncryptsec_off_thread(
            CRYPTSEC,
            "nostr",
            Some("/w.js"),
        ))
        .unwrap();
        assert_eq!(session.public_key.to_hex(), CRYPTSEC_PUBKEY);
    }
}
