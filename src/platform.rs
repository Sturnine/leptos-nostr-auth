#[cfg(not(feature = "ssr"))]
use wasm_bindgen::JsValue;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Android,
    Apple,
    Other,
}

#[derive(Clone, Copy, Debug)]
pub struct Platform {
    pub os: Os,
    pub has_nostr_extension: bool,
    /// `window.PublicKeyCredential` exists. PRF is confirmed by `prf_capability` where the browser
    /// reports it, and otherwise when a ceremony returns.
    pub supports_webauthn: bool,
}

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

            let supports_webauthn =
                js_sys::Reflect::get(&window, &JsValue::from_str("PublicKeyCredential"))
                    .is_ok_and(|v| !v.is_undefined() && !v.is_null());

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

/// The RP ID every ceremony uses: a non-empty configured value, else a non-empty hostname.
pub fn pick_rp_id(configured: Option<&str>, hostname: Option<String>) -> String {
    configured
        .filter(|rp_id| !rp_id.is_empty())
        .map(str::to_owned)
        .or_else(|| hostname.filter(|host| !host.is_empty()))
        .unwrap_or_else(|| "localhost".to_owned())
}

/// [`pick_rp_id`] with this page's hostname.
pub fn effective_rp_id(configured: Option<&str>) -> String {
    pick_rp_id(
        configured,
        web_sys::window().and_then(|w| w.location().hostname().ok()),
    )
}

#[cfg(not(feature = "ssr"))]
fn read_has_been_active(navigator: &JsValue) -> Option<bool> {
    let activation = js_sys::Reflect::get(navigator, &JsValue::from_str("userActivation")).ok()?;
    js_sys::Reflect::get(&activation, &JsValue::from_str("hasBeenActive"))
        .ok()?
        .as_bool()
}

// Sticky, not `isActive`: a press held past the 5 s transient window, or an earlier `window.open` in the handler, reads false inside a real click.
/// Whether the user has interacted with this document; `None` when the browser cannot say.
#[cfg(not(feature = "ssr"))]
pub fn page_has_been_active() -> Option<bool> {
    read_has_been_active(&JsValue::from(web_sys::window()?.navigator()))
}

/// Server stub for `page_has_been_active`.
#[cfg(feature = "ssr")]
pub const fn page_has_been_active() -> Option<bool> {
    None
}

/// `show_login` may prompt unless the browser says the user has not interacted yet.
pub fn prompt_allowed(been_active: Option<bool>) -> bool {
    been_active != Some(false)
}

/// `extension:prf` from `PublicKeyCredential.getClientCapabilities()`; `None` when unknown.
#[cfg(not(feature = "ssr"))]
pub async fn prf_capability() -> Option<bool> {
    use wasm_bindgen::JsCast as _;

    let window = web_sys::window()?;
    let class = js_sys::Reflect::get(&window, &JsValue::from_str("PublicKeyCredential")).ok()?;
    let capabilities = js_sys::Reflect::get(&class, &JsValue::from_str("getClientCapabilities"))
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()?
        .call0(&class)
        .ok()?
        .dyn_into::<js_sys::Promise>()
        .ok()?;
    let capabilities = wasm_bindgen_futures::JsFuture::from(capabilities)
        .await
        .ok()?;
    js_sys::Reflect::get(&capabilities, &JsValue::from_str("extension:prf"))
        .ok()?
        .as_bool()
}

/// Server stub for `prf_capability`.
#[cfg(feature = "ssr")]
pub async fn prf_capability() -> Option<bool> {
    None
}

/// Hide passkeys only when WebAuthn is absent or the browser says PRF is unavailable.
pub fn passkey_option_visible(has_public_key_credential: bool, prf: Option<bool>) -> bool {
    has_public_key_credential && prf != Some(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_rp_id_table() {
        let host = || Some("h".to_owned());
        assert_eq!(pick_rp_id(Some("rp"), host()), "rp");
        assert_eq!(pick_rp_id(Some("rp"), None), "rp");
        assert_eq!(pick_rp_id(Some(""), host()), "h");
        assert_eq!(pick_rp_id(None, host()), "h");
        assert_eq!(pick_rp_id(None, Some(String::new())), "localhost");
        assert_eq!(pick_rp_id(Some(""), Some(String::new())), "localhost");
        assert_eq!(pick_rp_id(None, None), "localhost");
    }

    #[test]
    fn passkey_option_visible_table() {
        assert!(passkey_option_visible(true, Some(true)));
        assert!(passkey_option_visible(true, None));
        assert!(!passkey_option_visible(true, Some(false)));
        assert!(!passkey_option_visible(false, Some(true)));
        assert!(!passkey_option_visible(false, None));
        assert!(!passkey_option_visible(false, Some(false)));
    }

    #[test]
    fn prompt_allowed_table() {
        assert!(prompt_allowed(Some(true)));
        assert!(!prompt_allowed(Some(false)));
        assert!(prompt_allowed(None));
    }
}

#[cfg(all(test, target_arch = "wasm32", not(feature = "ssr")))]
#[expect(clippy::unwrap_used, reason = "tests assert by unwrapping")]
mod wasm_tests {
    use super::*;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn activation_read_table() {
        for (navigator, want) in [
            ("({ userActivation: { hasBeenActive: true } })", Some(true)),
            (
                "({ userActivation: { hasBeenActive: false } })",
                Some(false),
            ),
            ("({ userActivation: { hasBeenActive: 'no' } })", None),
            (
                "({ userActivation: { get hasBeenActive() { throw new Error('x'); } } })",
                None,
            ),
            ("({ userActivation: null })", None),
            ("({})", None),
        ] {
            let navigator = js_sys::eval(navigator).unwrap();
            assert_eq!(read_has_been_active(&navigator), want);
        }
    }
}
