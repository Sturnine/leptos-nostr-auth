use leptos::prelude::*;
use leptos_nostr_auth::{AuthResult, NostrAuthConfig, NostrAuthProvider, use_nostr_auth};

#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}

pub fn shell(options: LeptosOptions) -> impl IntoView {
    #[cfg(feature = "ssr")]
    send_csp();
    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                <title>"Nostr Auth — Axum SSR Example"</title>
                <HydrationScripts options/>
                <link rel="stylesheet" href="/pkg/with-axum-ssr.css"/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

// The `ws://` sources are for cargo-leptos live reload and local relays.
#[cfg(feature = "ssr")]
fn send_csp() {
    use axum::http::{HeaderValue, header::CONTENT_SECURITY_POLICY};
    use leptos_axum::ResponseOptions;

    leptos::nonce::provide_nonce();
    let nonce = leptos::nonce::use_nonce().expect("provide_nonce just ran");
    let policy = format!(
        "default-src 'self'; script-src 'self' 'nonce-{nonce}' 'wasm-unsafe-eval'; \
         style-src 'self'; connect-src 'self' wss: ws://localhost:* ws://127.0.0.1:*; \
         img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    );
    expect_context::<ResponseOptions>().insert_header(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&policy).expect("the policy is visible ASCII"),
    );
}

#[component]
pub fn App() -> impl IntoView {
    let config = NostrAuthConfig {
        rp_name: "Nostr Auth Example".into(),
        ncryptsec_worker_url: Some("/nostr-auth-worker.js".into()),
        ..Default::default()
    };

    view! {
        <NostrAuthProvider config=config>
            <HomePage/>
        </NostrAuthProvider>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    let auth = use_nostr_auth();

    view! {
        <main class="page">
            <h1>"Nostr Auth — Axum SSR Example"</h1>
            <p class="subtitle">
                "Page HTML rendered server-side. After the WASM bundle loads, "
                "the login modal narrows to your real platform capabilities."
            </p>

            // A restore can wait a long time, so the login button below stays available beside it
            <Show when=move || auth.is_restoring.get() fallback=|| ()>
                <p class="restoring">"Restoring session…"</p>
            </Show>

            <Show
                when=move || auth.is_authenticated.get()
                fallback=move || view! {
                    <p>"Not logged in."</p>
                    <button
                        class="btn"
                        on:click=move |_| auth.show_login.run(())
                    >
                        "Login with Nostr"
                    </button>
                    <Show when=move || auth.has_saved_session.get() fallback=|| ()>
                        <p class="meta">
                            {move || {
                                auth.restore_error
                                    .get()
                                    .map(|e| format!("Saved session did not restore: {e}"))
                            }}
                        </p>
                        <button
                            class="btn btn-ghost"
                            on:click=move |_| auth.logout.run(())
                        >
                            "Forget saved session"
                        </button>
                    </Show>
                }
            >
                <p>
                    "Logged in via: "
                    <strong>
                        {move || auth.auth.with(|a| a.as_ref().map_or("", AuthResult::method_name))}
                    </strong>
                </p>
                <p>
                    "Public key: "
                    <code class="pubkey">
                        {move || auth.npub.get().unwrap_or_default()}
                    </code>
                </p>
                <button
                    class="btn btn-ghost"
                    on:click=move |_| auth.logout.run(())
                >
                    "Logout"
                </button>
            </Show>
        </main>
    }
}
