{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
      };
    };
    crane = {
      url = "github:ipetkov/crane";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        rust-overlay.follows = "rust-overlay";
        flake-utils.follows = "flake-utils";
      };
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
    flake-utils.lib.eachDefaultSystem
      (system:
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs {
            inherit system overlays;
          };
          rustToolchain = pkgs.pkgsBuildHost.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          # this is how we can tell crane to use our toolchain!
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          protoFilter = path: _type: builtins.match ".*proto$" path != null;
          tplFilter = path: _type: builtins.match ".*tpl$" path != null;
          sqlxFilter = path: _type: builtins.match ".*sqlx-data.json" path != null;
          protoOrCargo = path: type:
            (protoFilter path type) || (tplFilter path type) || (sqlxFilter path type) || (craneLib.filterCargoSources path type);
          src = pkgs.lib.cleanSourceWith {
            src = craneLib.path ./.; # The original, unfiltered source
            filter = protoOrCargo;
          }; # The original, unfiltered source
          nativeBuildInputs = with pkgs; [ rustToolchain pkg-config protobuf ];
          buildInputs = with pkgs; [ openssl wireguard-tools sudo iproute2 ];
          # because we'll use it for both `cargoArtifacts` and `bin`
          commonArgs = {
            inherit src buildInputs nativeBuildInputs;
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
          # remember, `set1 // set2` does a shallow merge:
          bin = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
          });
          dockerImage = pkgs.dockerTools.buildImage {
            name = "gateway";
            tag = "nix";
            copyToRoot = [ bin ];
            config = {
              Cmd = [ "${bin}/bin/defguard-gateway" ];
            };
          };
        in
        with pkgs;
        {
          packages =
            {
              # that way we can build `bin` specifically,
              # but it's also the default.
              inherit bin dockerImage;
              default = bin;
            };
          devShells.default = mkShell {
            inputsFrom = [ bin ];
          };
        }
      );
}
