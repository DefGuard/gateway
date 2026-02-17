{
  description = "Rust development flake";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs = {
    nixpkgs,
    flake-utils,
    rust-overlay,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      overlays = [(import rust-overlay)];
      pkgs = import nixpkgs {
        inherit system overlays;
      };
      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        extensions = ["rust-analyzer" "rust-src" "rustfmt" "clippy"];
        targets = ["x86_64-unknown-linux-gnu" "armv7-unknown-linux-gnueabihf" "aarch64-unknown-linux-gnu" "x86_64-unknown-freebsd"];
      };
    in {
      devShells.default = pkgs.mkShell {
        packages = with pkgs; [
          pkg-config
          openssl
          protobuf
          sqlx-cli
          rustToolchain
          libnftnl
          libmnl
          trivy
        ];
      };
    });
}
