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
          lockedWasmBindgen =
            (lib.findFirst (p: p.name == "wasm-bindgen") null (lib.importTOML ./Cargo.lock).package).version;
          wasmBindgenCli =
            assert lib.assertMsg (
              wasmBindgenVersion == lockedWasmBindgen
            ) "wasm-bindgen-cli ${wasmBindgenVersion} != wasm-bindgen ${lockedWasmBindgen} in Cargo.lock";
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
            env = {
              CC_wasm32_unknown_unknown = "${llvm.clang-unwrapped}/bin/clang";
              AR_wasm32_unknown_unknown = "${llvm.bintools-unwrapped}/bin/llvm-ar";
              CFLAGS_wasm32_unknown_unknown = "-isystem ${llvm.libclang.lib}/lib/clang/${clangMajor}/include";
            };
          };

          ssrArgs = commonArgs // {
            cargoExtraArgs = "--locked --features ssr";
          };
          hydrateArgs = commonArgs // {
            cargoExtraArgs = "--locked --target wasm32-unknown-unknown --features hydrate";
            doCheck = false;
          };

          ssrArtifacts = craneLib.buildDepsOnly ssrArgs;
          hydrateArtifacts = craneLib.buildDepsOnly hydrateArgs;
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [ inputs.rust-overlay.overlays.default ];
          };

          checks = {
            clippy-ssr = craneLib.cargoClippy (
              ssrArgs
              // {
                cargoArtifacts = ssrArtifacts;
                cargoClippyExtraArgs = "--all-targets --no-deps";
              }
            );
            clippy-hydrate = craneLib.cargoClippy (
              hydrateArgs
              // {
                cargoArtifacts = hydrateArtifacts;
                cargoClippyExtraArgs = "--no-deps";
              }
            );
            doc = craneLib.cargoDoc (
              ssrArgs
              // {
                cargoArtifacts = ssrArtifacts;
              }
            );
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
            ];
          };
        };
    };
}
