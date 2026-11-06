use js_sys::{Object, Promise, Reflect, Uint8Array};
use nostr::types::Timestamp;
use wasm_bindgen::prelude::*;

/// Create a Promise and extract its resolve/reject functions.
pub(super) fn make_rpc_promise() -> (Promise, js_sys::Function, js_sys::Function) {
    let mut settle = None;
    let promise = Promise::new(&mut |resolve, reject| settle = Some((resolve, reject)));
    #[expect(
        clippy::expect_used,
        reason = "the Promise constructor runs its executor synchronously"
    )]
    let (resolve, reject) = settle.expect("Promise executor did not run");
    (promise, resolve, reject)
}

/// Create a Promise that rejects with `"timeout"` after `timeout_secs` seconds.
#[expect(
    clippy::cast_possible_truncation,
    reason = "timeout_secs is a small config value, far below i32::MAX milliseconds"
)]
pub(super) fn make_timeout_promise(timeout_secs: u32) -> Promise {
    let timeout_ms = f64::from(timeout_secs) * 1000.0;
    Promise::new(&mut |_resolve, reject| {
        let cb = Closure::once(move || {
            let _ = reject.call1(&JsValue::UNDEFINED, &JsValue::from_str("timeout"));
        });
        #[expect(
            clippy::unwrap_used,
            reason = "a Promise executor cannot return a Result, and window exists whenever this module runs in a tab"
        )]
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                timeout_ms as i32,
            )
            .unwrap();
        cb.forget();
    })
}

/// `EventBuilder` reads time through universal-time's provider symbol, which this crate must not
/// require of wasm consumers.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "Date::now() is a non-negative millisecond count that fits u64"
)]
pub(super) fn now_timestamp() -> Timestamp {
    Timestamp::from_secs((js_sys::Date::now() / 1000.0) as u64)
}

/// Fill a `Vec<u8>` of the given length with cryptographically random bytes via
/// `window.crypto.getRandomValues`.
#[expect(
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    reason = "window and crypto exist in a tab, and callers pass 8-32 bytes, under the 64KiB quota and u32"
)]
pub(super) fn random_bytes(len: usize) -> Vec<u8> {
    let window = web_sys::window().unwrap();
    let crypto = window.crypto().unwrap();
    let mut buf = vec![0u8; len];
    let u8arr = Uint8Array::new_with_length(len as u32);
    crypto
        .get_random_values_with_array_buffer_view(&u8arr)
        .unwrap();
    u8arr.copy_to(&mut buf);
    buf
}

/// Extract a human-readable message from any JS error value.
pub(super) fn js_err_msg(e: &JsValue) -> String {
    e.as_string()
        .or_else(|| {
            Reflect::get(e, &"message".into())
                .ok()
                .and_then(|v| v.as_string())
        })
        .unwrap_or_else(|| format!("{e:?}"))
}

/// Set a property on a freshly-constructed, non-frozen JS object.
#[expect(
    clippy::unwrap_used,
    reason = "Reflect::set only fails on frozen targets; callers pass fresh plain objects"
)]
pub(super) fn set(obj: &Object, key: &str, val: &JsValue) {
    Reflect::set(obj, &key.into(), val).unwrap();
}

/// Set a string property on a freshly-constructed, non-frozen JS object.
#[expect(
    clippy::unwrap_used,
    reason = "Reflect::set only fails on frozen targets; callers pass fresh plain objects"
)]
pub(super) fn set_str(obj: &Object, key: &str, val: &str) {
    Reflect::set(obj, &key.into(), &JsValue::from_str(val)).unwrap();
}

#[cfg(test)]
#[cfg(target_arch = "wasm32")]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_futures::JsFuture;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    async fn rpc_promise_settles_through_its_functions() {
        let (ok, resolve, _) = make_rpc_promise();
        resolve
            .call1(&JsValue::UNDEFINED, &JsValue::from_str("done"))
            .unwrap();
        let value = JsFuture::from(ok).await.unwrap();
        assert_eq!(value.as_string().unwrap(), "done");
        let (failed, _, reject) = make_rpc_promise();
        reject
            .call1(&JsValue::UNDEFINED, &JsValue::from_str("nope"))
            .unwrap();
        let error = JsFuture::from(failed).await.unwrap_err();
        assert_eq!(error.as_string().unwrap(), "nope");
    }
}
