#[tokio::main]
async fn main() {
    use axum::Router;
    use leptos_axum::{LeptosRoutes, generate_route_list};
    use tower_http::services::ServeDir;
    use with_axum_ssr::{App, shell};

    let conf = leptos::config::get_configuration(None).expect("Failed to read the Leptos environment set by cargo-leptos");
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(App);

    let app = Router::new()
        .leptos_routes(&leptos_options, routes, {
            let opts = leptos_options.clone();
            move || shell(opts.clone())
        })
        .fallback(leptos_axum::file_and_error_handler(shell))
        .nest_service(
            "/pkg",
            ServeDir::new(format!("{}/pkg", leptos_options.site_root)),
        )
        .with_state(leptos_options);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind");
    println!("Listening on http://localhost:{}", addr.port());
    axum::serve(listener, app).await.expect("Server error");
}
