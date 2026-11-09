use leptos::prelude::*;
use leptos_nostr_auth::nostr::event::{FinalizeEventAsync, Kind, UnsignedEvent};
use leptos_nostr_auth::nostr::key::{AsyncGetPublicKey, PublicKey};
use leptos_nostr_auth::nostr::types::Timestamp;
use leptos_nostr_auth::{AuthResult, NostrAuthConfig, NostrAuthProvider, use_nostr_auth};

fn test_event(pubkey: PublicKey) -> UnsignedEvent {
    UnsignedEvent::new(
        pubkey,
        Timestamp::from_secs((js_sys::Date::now() / 1000.0) as u64),
        Kind::TextNote,
        [],
        "Hello from leptos-nostr-auth!",
    )
}

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(|| view! { <App /> });
}

#[component]
fn App() -> impl IntoView {
    let config = NostrAuthConfig {
        rp_name: "Nostr Auth Example".into(),
        ncryptsec_worker_url: Some("/nostr-auth-worker_loader.js".into()),
        ..Default::default()
    };

    view! {
        <NostrAuthProvider config=config>
            <HomePage />
        </NostrAuthProvider>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    let auth = use_nostr_auth();

    view! {
        <main class="page">
            <h1>"Nostr Auth — Basic Example"</h1>

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

                <Show
                    when=move || auth.auth.with(|a| a.as_ref().is_some_and(AuthResult::can_sign))
                    fallback=|| view! { <p class="meta">"(Read-only — cannot sign)"</p> }
                >
                    <SignDemo />
                </Show>

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

// Rendered inside the `can_sign` `Show`, so logout disposes `sign_output` with the session.
#[component]
fn SignDemo() -> impl IntoView {
    let auth = use_nostr_auth();
    let (sign_output, set_sign_output) = signal(String::new());

    view! {
        <button
            class="btn"
            on:click=move |_| {
                if let Some(auth_result) = auth.auth.get_untracked() {
                    let event_json = test_event(auth_result.public_key()).as_json();
                    set_sign_output.set("Signing…".into());
                    wasm_bindgen_futures::spawn_local(async move {
                        let output = match auth_result.sign_event(&event_json).await {
                            Ok(signed) => {
                                let preview: String = signed.chars().take(80).collect();
                                format!("Signed: {preview}…")
                            }
                            Err(e) => format!("Error: {e}"),
                        };
                        _ = set_sign_output.try_set(output);
                    });
                }
            }
        >
            "Sign test event"
        </button>
        <button
            class="btn"
            on:click=move |_| {
                if let Some(auth_result) = auth.auth.get_untracked() {
                    set_sign_output.set("Signing…".into());
                    wasm_bindgen_futures::spawn_local(async move {
                        let signed = match auth_result.get_public_key_async().await {
                            Ok(pubkey) => {
                                test_event(pubkey)
                                    .finalize_async(&auth_result)
                                    .await
                                    .map_err(|e| e.to_string())
                            }
                            Err(e) => Err(e.to_string()),
                        };
                        let output = match signed {
                            Ok(event) => event.as_json(),
                            Err(e) => format!("Error: {e}"),
                        };
                        _ = set_sign_output.try_set(output);
                    });
                }
            }
        >
            "Sign with finalize_async"
        </button>
        <Show when=move || sign_output.with(|s| !s.is_empty()) fallback=|| ()>
            <pre class="signed-output">
                {move || sign_output.get()}
            </pre>
        </Show>
    }
}
