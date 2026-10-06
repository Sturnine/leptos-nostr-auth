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
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          craneLib = (inputs.crane.mkLib pkgs).overrideToolchain (
            p: p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml
          );

          llvm = pkgs.llvmPackages;
          clangMajor = lib.versions.major llvm.clang-unwrapped.version;

          wasmBindgenVersion = "0.2.121";
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
                hash = "sha256-ZOMgFNOcGkO66Jz/Z83eoIu+DIzo3Z/vq6Z5g6BDY/w=";
              };
              cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
                inherit src;
                inherit (src) pname version;
                hash = "sha256-DPdCDPTAPBrbqLUqnCwQu1dePs9lGg85JCJOCIr9qjU=";
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
                cargoClippyExtraArgs = "--all-targets --no-deps -- --deny warnings";
              }
            );
            clippy-hydrate = craneLib.cargoClippy (
              hydrateArgs
              // {
                cargoArtifacts = hydrateArtifacts;
                cargoClippyExtraArgs = "--no-deps -- --deny warnings";
              }
            );
            doc = craneLib.cargoDoc (
              ssrArgs
              // {
                cargoArtifacts = ssrArtifacts;
                env = ssrArgs.env // {
                  RUSTDOCFLAGS = "--deny warnings";
                };
              }
            );
          };

          treefmt = {
            projectRootFile = "flake.nix";
            programs = {
              rustfmt = {
                enable = true;
                package = rustToolchain;
                edition = (lib.importTOML ./Cargo.toml).package.edition;
              };
              nixfmt.enable = true;
              taplo.enable = true;
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
