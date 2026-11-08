#![expect(clippy::unwrap_used, reason = "test helper")]
use js_sys::{Array, Function, Object, Promise, Reflect};
use wasm_bindgen::{JsCast as _, JsValue};
use wasm_bindgen_futures::JsFuture;

// `wss://hang.*` never opens; any other URL opens after 5 ms.
pub fn install() {
    js_sys::eval(
        r"globalThis.window = globalThis;
        globalThis.Window = class { static [Symbol.hasInstance]() { return true; } };
        if (!globalThis.__st) { const st = setTimeout, ct = clearTimeout; globalThis.__st = true;
          globalThis.setTimeout = (f, ms) => Number(st(f, ms));
          globalThis.clearTimeout = (id) => ct(id); }
        globalThis.__ws = [];
        globalThis.WebSocket = class {
          constructor(url) {
            this.url = url; this.readyState = 0; this.sent = []; this.seen = 0; globalThis.__ws.push(this);
            if (!url.includes('hang')) setTimeout(() => {
              if (this.readyState !== 0) return;
              this.readyState = 1; if (this.onopen) this.onopen({});
            }, 5);
          }
          send(s) { this.sent.push(s); }
          close() { this.readyState = 3; }
        };",
    )
    .unwrap();
}

pub fn sockets() -> Array {
    js_sys::eval("globalThis.__ws").unwrap().unchecked_into()
}

pub fn opened_urls() -> Vec<String> {
    sockets()
        .iter()
        .map(|ws| {
            Reflect::get(&ws, &"url".into())
                .unwrap()
                .as_string()
                .unwrap()
        })
        .collect()
}

pub fn forget_sockets() {
    js_sys::eval("globalThis.__ws = []").unwrap();
}

/// Frames sent on `ws` since the last call.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "a JS array length"
)]
pub fn take_sent(ws: &JsValue) -> Vec<String> {
    let sent: Array = Reflect::get(ws, &"sent".into()).unwrap().unchecked_into();
    let seen = Reflect::get(ws, &"seen".into()).unwrap().as_f64().unwrap() as u32;
    Reflect::set(ws, &"seen".into(), &f64::from(sent.length()).into()).unwrap();
    (seen..sent.length())
        .map(|i| sent.get(i).as_string().unwrap())
        .collect()
}

pub fn deliver(ws: &JsValue, frame: &str) {
    let event = Object::new();
    Reflect::set(&event, &"data".into(), &frame.into()).unwrap();
    Reflect::set(&event, &"target".into(), ws).unwrap();
    let on: Function = Reflect::get(ws, &"onmessage".into())
        .unwrap()
        .unchecked_into();
    on.call1(ws, &event).unwrap();
}

pub async fn tick(ms: u32) {
    let p = Promise::new(&mut |res, _| {
        let f: Function = Reflect::get(&js_sys::global(), &"setTimeout".into())
            .unwrap()
            .unchecked_into();
        f.call2(&JsValue::NULL, &res, &ms.into()).unwrap();
    });
    JsFuture::from(p).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use std::rc::Rc;
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen_test::wasm_bindgen_test;
    use web_sys::{MessageEvent, WebSocket};

    #[wasm_bindgen_test]
    async fn fake_socket_opens_within_50_ms() {
        install();
        let ws = WebSocket::new("wss://ok.example").unwrap();
        tick(50).await;
        assert_eq!(ws.ready_state(), WebSocket::OPEN);
    }

    #[wasm_bindgen_test]
    async fn fake_socket_records_frames_and_delivers_messages() {
        install();
        let ws = WebSocket::new("wss://ok.example").unwrap();
        let hang = WebSocket::new("wss://hang.example").unwrap();
        tick(50).await;
        assert_eq!(hang.ready_state(), WebSocket::CONNECTING);
        assert_eq!(opened_urls(), ["wss://ok.example", "wss://hang.example"]);
        ws.send_with_str("one").unwrap();
        let raw: &JsValue = ws.as_ref();
        assert_eq!(take_sent(raw), ["one"]);
        assert_eq!(take_sent(raw), Vec::<String>::new());
        let got = Rc::new(RefCell::new(Vec::new()));
        let sink = Rc::clone(&got);
        let on = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
            sink.borrow_mut().push(e.data().as_string().unwrap());
        });
        ws.set_onmessage(Some(on.as_ref().unchecked_ref()));
        deliver(raw, "frame");
        assert_eq!(*got.borrow(), ["frame"]);
        assert_eq!(sockets().length(), 2);
        forget_sockets();
        assert_eq!(sockets().length(), 0);
    }
}
