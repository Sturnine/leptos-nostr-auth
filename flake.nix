{
  description = "leptos-nostr-auth - Headless Nostr authentication components for Leptos";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    inputs.flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      imports = [ inputs.treefmt-nix.flakeModule ];

      perSystem =
        {
          config,
          self',
          pkgs,
          lib,
          system,
          ...
        }:
        let
          craneLib = (inputs.crane.mkLib pkgs).overrideToolchain (
            p: p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml
          );

          llvm = pkgs.llvmPackages;
          clangMajor = lib.versions.major llvm.clang-unwrapped.version;

          wasmBindgenVersion = "0.2.130";
          wasmBindgenVersions =
            f:
            map (p: p.version) (
              lib.filter (p: p.name == "wasm-bindgen") (lib.importTOML (./. + "/${f}")).package
            );
          wasmBindgenMismatches = lib.filter (f: wasmBindgenVersions f != [ wasmBindgenVersion ]) [
            "Cargo.lock"
            "examples/basic-csr/Cargo.lock"
            "examples/with-axum-ssr/Cargo.lock"
          ];
          wasmBindgenCli =
            assert lib.assertMsg (wasmBindgenMismatches == [ ])
              "wasm-bindgen-cli ${wasmBindgenVersion} does not match: ${lib.concatStringsSep ", " wasmBindgenMismatches}";
            pkgs.buildWasmBindgenCli rec {
              src = pkgs.fetchCrate {
                pname = "wasm-bindgen-cli";
                version = wasmBindgenVersion;
                hash = "sha256-9Og1O/6/VC3sc5hBjoIWBErmLW2UHGMsTQO+6+m/dng=";
              };
              cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
                inherit src;
                inherit (src) pname version;
                hash = "sha256-j81sUf1m5yXU4FJfGj7GV+hdqVCV8mRmNb0QIsMCjqw=";
              };
            };

          commonArgs = {
            src = craneLib.cleanCargoSource ./.;
            strictDeps = true;
            # secp256k1-sys compiles C for wasm32, which the cc-wrapper clang can't target.
            # Tests keep overflow checks and match `cargo test`.
            CARGO_PROFILE = "";
            env = {
              CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER = "wasm-bindgen-test-runner";
              CC_wasm32_unknown_unknown = "${llvm.clang-unwrapped}/bin/clang";
              AR_wasm32_unknown_unknown = "${llvm.bintools-unwrapped}/bin/llvm-ar";
              CFLAGS_wasm32_unknown_unknown = "-isystem ${llvm.libclang.lib}/lib/clang/${clangMajor}/include";
            };
          };

          nativeArgs = commonArgs // {
            cargoExtraArgs = "--locked";
          };
          ssrArgs = commonArgs // {
            cargoExtraArgs = "--locked --features ssr";
          };
          hydrateArgs = commonArgs // {
            cargoExtraArgs = "--locked --target wasm32-unknown-unknown --features hydrate";
            doCheck = false;
          };
          csrArgs = commonArgs // {
            cargoExtraArgs = "--locked --target wasm32-unknown-unknown --features csr";
            doCheck = false;
          };
          withNsec = args: args // { cargoExtraArgs = args.cargoExtraArgs + ",insecure_nsec_input"; };
          leaf = {
            doInstallCargoArtifacts = false;
          };

          nativeArtifacts = craneLib.buildDepsOnly nativeArgs;
          ssrArtifacts = craneLib.buildDepsOnly ssrArgs;
          hydrateArtifacts = craneLib.buildDepsOnly hydrateArgs;
          csrArtifacts = craneLib.buildDepsOnly csrArgs;

          clippy =
            args: cargoArtifacts: targets:
            craneLib.cargoClippy (
              args
              // leaf
              // {
                inherit cargoArtifacts;
                cargoClippyExtraArgs = "${targets} --no-deps -- --deny warnings";
              }
            );

          mkExample =
            dir: cargoExtraArgs:
            let
              args = commonArgs // {
                inherit cargoExtraArgs;
                cargoToml = ./examples/${dir}/Cargo.toml;
                cargoLock = ./examples/${dir}/Cargo.lock;
                postUnpack = ''
                  cd $sourceRoot/examples/${dir}
                  sourceRoot="."
                '';
                doCheck = false;
              };
            in
            craneLib.cargoBuild (args // leaf // { cargoArtifacts = craneLib.buildDepsOnly args; });
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.rust-overlay.overlays.default ];
          };

          checks = {
            clippy-ssr = clippy ssrArgs ssrArtifacts "--all-targets";
            clippy-ssr-nsec = clippy (withNsec ssrArgs) ssrArtifacts "--all-targets";
            clippy-hydrate = clippy hydrateArgs hydrateArtifacts "";
            clippy-hydrate-nsec = clippy (withNsec hydrateArgs) hydrateArtifacts "";
            clippy-csr = clippy csrArgs csrArtifacts "--all-targets";
            clippy-csr-nsec = clippy (withNsec csrArgs) csrArtifacts "";
            clippy-native = clippy nativeArgs nativeArtifacts "--all-targets";

            doc = craneLib.cargoDoc (
              ssrArgs
              // leaf
              // {
                cargoArtifacts = ssrArtifacts;
                env = ssrArgs.env // {
                  RUSTDOCFLAGS = "--deny warnings";
                };
              }
            );

            test = craneLib.cargoTest (nativeArgs // leaf // { cargoArtifacts = nativeArtifacts; });
            test-ssr = craneLib.cargoTest (ssrArgs // leaf // { cargoArtifacts = ssrArtifacts; });
            # Runs under Node: no window, localStorage, credentials or WebSocket.
            test-wasm = craneLib.cargoTest (
              csrArgs
              // leaf
              // {
                cargoArtifacts = csrArtifacts;
                doCheck = true;
                cargoTestExtraArgs = "--lib";
                nativeBuildInputs = [
                  wasmBindgenCli
                  pkgs.nodejs
                ];
              }
            );

            example-basic-csr = mkExample "basic-csr" "--locked --target wasm32-unknown-unknown";
            example-axum-ssr = mkExample "with-axum-ssr" "--locked --features ssr --bin with-axum-ssr";
            example-axum-hydrate = mkExample "with-axum-ssr" "--locked --target wasm32-unknown-unknown --features hydrate --lib";

            audit = craneLib.cargoAudit {
              inherit (inputs) advisory-db;
              inherit (commonArgs) src;
            };
          };

          treefmt = {
            projectRootFile = "flake.nix";
            programs = {
              rustfmt = {
                enable = true;
                package = craneLib.rustfmt;
                edition = (lib.importTOML ./Cargo.toml).package.edition;
              };
              nixfmt.enable = true;
              taplo = {
                enable = true;
                settings.formatting = {
                  align_entries = true;
                  column_width = 100;
                };
              };
            };
          };

          devShells.default = craneLib.devShell {
            checks = self'.checks;
            inherit (commonArgs) env;
            packages = [
              config.treefmt.build.wrapper
              wasmBindgenCli
              pkgs.cargo-leptos
              pkgs.trunk
              pkgs.binaryen
              pkgs.nodejs
            ];
          };
        };
    };
}
