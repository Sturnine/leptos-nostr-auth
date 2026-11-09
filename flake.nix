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

          msrvCraneLib = (inputs.crane.mkLib pkgs).overrideToolchain (
            p:
            p.rust-bin.stable.${(lib.importTOML ./Cargo.toml).package.rust-version + ".0"}.minimal.override {
              targets = [ "wasm32-unknown-unknown" ];
            }
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
            # README.md is compiled as doctests.
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [
                (craneLib.fileset.commonCargoSources ./.)
                ./README.md
              ];
            };
            strictDeps = true;
            # Tests keep overflow checks and match `cargo test`.
            CARGO_PROFILE = "";
            env = {
              CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER = "wasm-bindgen-test-runner";
              # secp256k1-sys compiles C for wasm32, which the cc-wrapper clang can't target.
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
          csrTachysSsrArgs = commonArgs // {
            cargoExtraArgs = "--locked --features csr,insecure_nsec_input,leptos/ssr";
            env = ssrArgs.env // {
              CARGO_PROFILE_DEV_OPT_LEVEL = "0";
            };
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

          auditExample =
            dir:
            craneLib.cargoAudit {
              inherit (inputs) advisory-db;
              src = craneLib.cleanCargoSource ./.;
              cargoLock = ./examples/${dir}/Cargo.lock;
            };

          msrvCheck =
            args: cargoArtifacts:
            msrvCraneLib.cargoBuild (
              args
              // leaf
              // {
                inherit cargoArtifacts;
                buildPhaseCargoCommand = "cargoWithProfile check ${args.cargoExtraArgs}";
                installPhaseCommand = "mkdir -p $out";
              }
            );

          msrvSsrArgs = commonArgs // {
            cargoExtraArgs = "--locked --features ssr";
          };
          msrvCsrArgs = commonArgs // {
            cargoExtraArgs = "--locked --target wasm32-unknown-unknown --features csr --lib";
          };
          msrvSsrArtifacts = msrvCraneLib.buildDepsOnly msrvSsrArgs;
          msrvCsrArtifacts = msrvCraneLib.buildDepsOnly msrvCsrArgs;
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.rust-overlay.overlays.default ];
          };

          # CI builds this with an out-link so cache-nix-action's `nix store gc` keeps the
          # dependency builds; `nix flake check` leaves its outputs unrooted.
          packages.ci-roots = pkgs.linkFarm "ci-roots" (
            lib.mapAttrs (_: check: check.cargoArtifacts) (
              lib.filterAttrs (_: check: check.cargoArtifacts or null != null) config.checks
            )
          );

          checks = {
            clippy-ssr = clippy ssrArgs ssrArtifacts "--all-targets";
            clippy-ssr-nsec = clippy (withNsec ssrArgs) ssrArtifacts "--all-targets";
            clippy-hydrate = clippy hydrateArgs hydrateArtifacts "";
            clippy-hydrate-nsec = clippy (withNsec hydrateArgs) hydrateArtifacts "--all-targets";
            clippy-csr = clippy csrArgs csrArtifacts "--all-targets";
            clippy-csr-nsec = clippy (withNsec csrArgs) csrArtifacts "--all-targets";
            clippy-native = clippy nativeArgs nativeArtifacts "--all-targets";

            doc = craneLib.cargoDoc (
              withNsec ssrArgs
              // leaf
              // {
                cargoArtifacts = ssrArtifacts;
                env = ssrArgs.env // {
                  RUSTDOCFLAGS = "--deny warnings";
                };
              }
            );

            test = craneLib.cargoTest (nativeArgs // leaf // { cargoArtifacts = nativeArtifacts; });
            test-ssr = craneLib.cargoTest ((withNsec ssrArgs) // leaf // { cargoArtifacts = ssrArtifacts; });
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

            # The depth overflow appears only at codegen; check and clippy miss it.
            build-csr-tachys-ssr = craneLib.cargoBuild (
              csrTachysSsrArgs // leaf // { cargoArtifacts = craneLib.buildDepsOnly csrTachysSsrArgs; }
            );

            example-basic-csr = mkExample "basic-csr" "--locked --target wasm32-unknown-unknown";
            example-axum-ssr = mkExample "with-axum-ssr" "--locked --features ssr --bin with-axum-ssr";
            example-axum-hydrate = mkExample "with-axum-ssr" "--locked --target wasm32-unknown-unknown --features hydrate --lib";

            audit = craneLib.cargoAudit {
              inherit (inputs) advisory-db;
              inherit (commonArgs) src;
            };
            audit-example-basic-csr = auditExample "basic-csr";
            audit-example-axum-ssr = auditExample "with-axum-ssr";

            msrv-ssr = msrvCheck msrvSsrArgs msrvSsrArtifacts;
            msrv-csr = msrvCheck msrvCsrArgs msrvCsrArtifacts;

            workflows =
              pkgs.runCommand "workflows"
                {
                  src = lib.fileset.toSource {
                    root = ./.;
                    fileset = lib.fileset.unions [
                      ./.github
                      ./scripts
                    ];
                  };
                  nativeBuildInputs = [
                    pkgs.actionlint
                    pkgs.shellcheck
                    pkgs.zizmor
                  ];
                }
                ''
                  cd "$src"
                  actionlint .github/workflows/*.yml
                  shellcheck scripts/*.sh
                  zizmor --offline --persona pedantic .
                  touch "$out"
                '';
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
