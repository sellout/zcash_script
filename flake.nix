{
  description = "Zcash transparent script implementations.";

  nixConfig = {
    extra-experimental-features = ["no-url-literals"];
    use-registries = false;
    sandbox = "relaxed";
  };

  outputs = {
    advisory-db,
    crane,
    fenix,
    flake-utils,
    home-manager,
    nix-darwin,
    nixpkgs,
    rust-overlay,
    self,
    systems,
  }: let
    supportedSystems = import systems;

    lib = import ./nix/lib {
      inherit crane;
      inherit (nixpkgs) lib;
    };

    src = nixpkgs.lib.cleanSourceWith {
      src = ./.;
      filter = path: type:
        nixpkgs.lib.foldr
        (e: acc: nixpkgs.lib.hasSuffix e path || acc)
          true []
        || lib.crane.filterCargoSources path type;
    };

    mkCraneLib = pkgs:
      (crane.mkLib pkgs).overrideToolchain (import ./nix/rust-toolchain.nix {inherit fenix pkgs;});

    localPackages = {
      pkgs,
      craneLib ? crane.mkLib pkgs,
    }:
      import ./nix/packages {
        inherit craneLib src;
        inherit (pkgs) callPackage;
      };
  in
    {
      overlays.default = final: prev: localPackages {pkgs = final;};
    }
    // flake-utils.lib.eachSystem supportedSystems (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [(import rust-overlay)];
      };

      craneLib = crane.mkLib pkgs;

      packages = localPackages {inherit craneLib pkgs;};

      cargoArtifacts = packages.zcash_script-dependencies;
    in {
      packages =
        {default = self.packages.${system}.zcash_script;}
        // packages;

      devShells.default = craneLib.devShell {
        checks = self.checks.${system};
        inputsFrom = builtins.attrValues self.packages.${system};
        packages = [
          pkgs.home-manager
          pkgs.rust-analyzer
        ];
        LIBCLANG_PATH = pkgs.libclang.lib + "/lib";
      };

      checks = import ./nix/checks.nix {
        inherit advisory-db cargoArtifacts craneLib pkgs src;
        inherit (nixpkgs) lib;
      };

      formatter = pkgs.alejandra;
    });

  inputs = {
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };

    crane.url = "github:ipetkov/crane";

    fenix = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "github:nix-community/fenix";
    };

    flake-utils = {
      inputs.systems.follows = "systems";
      url = "github:numtide/flake-utils";
    };

    home-manager = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "github:nix-community/home-manager/release-24.11";
    };

    nix-darwin = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "github:LnL7/nix-darwin";
    };

    nixpkgs.url = "github:NixOS/nixpkgs/release-24.11";

    rust-overlay = {
      inputs.nixpkgs.follows = "nixpkgs";
      url = "github:oxalica/rust-overlay";
    };

    systems.url = "github:nix-systems/default";
  };
}
