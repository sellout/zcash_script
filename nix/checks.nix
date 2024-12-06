{
  advisory-db,
  cargoArtifacts,
  craneLib,
  lib,
  pkgs,
  src,
}: {
  # audit = craneLib.cargoAudit {inherit advisory-db src;};

  clippy = craneLib.cargoClippy {
      inherit cargoArtifacts src;
      buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
        pkgs.darwin.apple_sdk.frameworks.Security
        pkgs.libiconv
      ];
      nativeBuildInputs = [pkgs.protobuf];
      LIBCLANG_PATH = pkgs.libclang.lib + "/lib";
      cargoClippyExtraArgs = "--all-targets"; # -- --deny warnings";
    };

  deny = craneLib.cargoDeny {
      inherit src;
      cargoDenyChecks = lib.concatStringsSep " " ["bans" "sources"];
    };

  doc = craneLib.cargoDoc {
      inherit cargoArtifacts src;
      buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
        pkgs.darwin.apple_sdk.frameworks.Security
        pkgs.libiconv
      ];
      nativeBuildInputs = [pkgs.protobuf];
      LIBCLANG_PATH = pkgs.libclang.lib + "/lib";
    };

  fmt = craneLib.cargoFmt {inherit src;};

  ## Can only fuzz with nightly at the moment.
  fuzz = (craneLib.overrideToolchain (p: p.rust-bin.nightly.latest.default)).mkCargoDerivation {
    inherit cargoArtifacts src;

    pnameSuffix = "-fuzz";

    buildPhaseCargoCommand = ''
      # This `max_len` should be enough to overflow script length sometimes.
      cargo fuzz run compare -- -max_len=20000 -max_total_time=100 -dict=fuzz/dictionary
    '';

    nativeBuildInputs = [ pkgs.cargo-fuzz ];

    LIBCLANG_PATH = pkgs.libclang.lib + "/lib";
  };

  # toml-fmt = craneLib.taploFmt {src = lib.sources.sourceFilesBySuffices src [".toml"];};
}
