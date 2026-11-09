import init, { leptosNostrAuthNcryptsecWorker } from "/pkg/with-axum-ssr.js";
await init({ module_or_path: "/pkg/with-axum-ssr.wasm" });
leptosNostrAuthNcryptsecWorker();
