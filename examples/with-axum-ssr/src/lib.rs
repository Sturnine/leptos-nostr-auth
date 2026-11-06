use leptos::prelude::*;
use leptos_nostr_auth::{NostrAuthConfig, NostrAuthProvider, use_nostr_auth};

// Hydrate entry — browser calls this after loading the WASM bundle.
// wasm_bindgen exports it so the JS glue code can invoke it on startup.
#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}

/// HTML shell — server renders this as the full outer document.
/// `HydrationScripts` injects the WASM bundle URL + serialized reactive state.
pub fn shell(options: LeptosOptions) -> impl IntoView {
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

#[component]
pub fn App() -> impl IntoView {
    let config = NostrAuthConfig {
        persist_session: true,
        rp_id: Some("localhost".into()),
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

            // Restoring indicator — avoids login button flash on page load
            <Show when=move || auth.is_restoring.get() fallback=|| ()>
                <p class="restoring">"Restoring session…"</p>
            </Show>

            <Show
                when=move || auth.is_authenticated.get()
                fallback=move || view! {
                    <Show when=move || !auth.is_restoring.get() fallback=|| ()>
                        <p>"Not logged in."</p>
                        <button
                            class="btn"
                            on:click=move |_| auth.show_login.run(())
                        >
                            "Login with Nostr"
                        </button>
                    </Show>
                }
            >
                <p>
                    "Logged in via: "
                    <strong>
                        {move || auth.auth.get().map_or("", |a| a.method_name())}
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
