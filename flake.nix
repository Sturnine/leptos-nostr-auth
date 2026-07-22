{
  description = "leptos-nostr-auth - Headless Nostr authentication components for Leptos";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      pkgs = import nixpkgs {
        system = "aarch64-darwin";
      };
    in
    {
      devShells.aarch64-darwin.default = pkgs.mkShell {
        nativeBuildInputs = with pkgs; [
          cargo
          cargo-edit
          cargo-leptos
          trunk
          rustc
          rustfmt
          clippy
          rust-analyzer
          llvmPackages.llvm
          llvmPackages.libclang
          llvmPackages.clang-unwrapped
          lld
          (pkgs.callPackage buildWasmBindgenCli rec {
            src = fetchCrate {
              pname = "wasm-bindgen-cli";
              version = "0.2.121";
              hash = "sha256-ZOMgFNOcGkO66Jz/Z83eoIu+DIzo3Z/vq6Z5g6BDY/w=";
            };

            cargoDeps = rustPlatform.fetchCargoVendor {
              inherit src;
              inherit (src) pname version;
              hash = "sha256-DPdCDPTAPBrbqLUqnCwQu1dePs9lGg85JCJOCIr9qjU=";
            };
          })
        ];

        shellHook = with pkgs; ''
          export CC_wasm32_unknown_unknown=${llvmPackages.clang-unwrapped}/bin/clang-21
          export CFLAGS_wasm32_unknown_unknown="-I ${llvmPackages.libclang.lib}/lib/clang/21/include/"
          export PATH="/opt/homebrew/opt/llvm/bin/:$PATH"
          export CC=${llvmPackages.clang}/bin/clang
          export AR=${llvmPackages.bintools-unwrapped}/bin/llvm-ar
        '';
      };
    };
}
