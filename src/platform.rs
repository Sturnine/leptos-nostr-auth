#[cfg(not(feature = "ssr"))]
use wasm_bindgen::JsValue;

/// Detected operating system family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    /// Android user-agent.
    Android,
    /// macOS or iOS/iPadOS user-agent.
    Apple,
    /// Any other platform (Linux, Windows, unknown).
    Other,
}

/// Runtime platform capabilities detected once at startup.
#[derive(Clone, Copy, Debug)]
pub struct Platform {
    /// Detected OS family.
    pub os: Os,
    /// `window.nostr` is present (NIP-07 browser extension installed)
    pub has_nostr_extension: bool,
    /// `navigator.credentials` exists (WebAuthn is available; PRF confirmed at runtime)
    pub supports_webauthn: bool,
}

/// Try `navigator.userAgentData.platform` (Client Hints, Chrome/Edge only).
/// Returns `None` if the API is absent (Firefox, Safari) or returns an empty string.
#[cfg(not(feature = "ssr"))]
fn os_from_ua_data(navigator: &web_sys::Navigator) -> Option<Os> {
    let ua_data = js_sys::Reflect::get(
        &JsValue::from(navigator.clone()),
        &JsValue::from_str("userAgentData"),
    )
    .ok()?;

    if ua_data.is_undefined() || ua_data.is_null() {
        return None;
    }

    let platform = js_sys::Reflect::get(&ua_data, &JsValue::from_str("platform"))
        .ok()
        .and_then(|v| v.as_string())?;

    if platform.is_empty() {
        return None;
    }

    Some(match platform.to_lowercase().as_str() {
        "android" => Os::Android,
        "ios" | "macos" => Os::Apple,
        _ => Os::Other,
    })
}

/// Fallback: parse `navigator.userAgent` string (all browsers).
#[cfg(not(feature = "ssr"))]
fn os_from_ua_string(navigator: &web_sys::Navigator) -> Os {
    let ua = navigator.user_agent().unwrap_or_default().to_lowercase();
    let is_android = ua.contains("android");
    // iPadOS 13+ reports as Macintosh in desktop mode, so check ipad too.
    let is_apple =
        (ua.contains("macintosh") || ua.contains("iphone") || ua.contains("ipad")) && !is_android;
    if is_android {
        Os::Android
    } else if is_apple {
        Os::Apple
    } else {
        Os::Other
    }
}

impl Platform {
    /// Detect platform capabilities from browser APIs.
    ///
    /// In SSR mode returns `server_default()` immediately (no browser APIs available).
    /// Call inside `Effect::new()` and write to a reactive signal so the UI narrows
    /// down from the full server-rendered list after hydration.
    #[cfg_attr(
        feature = "ssr",
        expect(
            clippy::missing_const_for_fn,
            reason = "const only under ssr; the browser build calls non-const APIs"
        )
    )]
    pub fn detect() -> Self {
        #[cfg(feature = "ssr")]
        {
            Self::server_default()
        }

        #[cfg(not(feature = "ssr"))]
        {
            let Some(window) = web_sys::window() else {
                return Self::server_default();
            };

            let has_nostr_extension =
                js_sys::Reflect::has(&JsValue::from(window.clone()), &JsValue::from_str("nostr"))
                    .unwrap_or(false);

            let navigator = window.navigator();

            let os = os_from_ua_data(&navigator).unwrap_or_else(|| os_from_ua_string(&navigator));

            // WebAuthn availability: navigator.credentials must exist.
            // Actual PRF support is confirmed when credentials.create() returns PRF results.
            let supports_webauthn = {
                let creds = js_sys::Reflect::get(
                    &JsValue::from(navigator),
                    &JsValue::from_str("credentials"),
                )
                .ok();
                matches!(creds, Some(ref v) if !v.is_undefined() && !v.is_null())
            };

            Self {
                os,
                has_nostr_extension,
                supports_webauthn,
            }
        }
    }

    /// Used on the server and as the pre-hydration initial state on the client.
    ///
    /// All visibility flags are `true` so the server renders the complete method list.
    /// `os` is `Other` for neutral ordering (no Apple-first layout, no Amber tip).
    /// After hydration, `Effect::new()` calls `detect()` and updates the platform
    /// signal, reactively narrowing the list to real capabilities.
    pub(crate) const fn server_default() -> Self {
        Self {
            os: Os::Other,
            has_nostr_extension: true,
            supports_webauthn: true,
        }
    }
}
