{
  cargoArtifacts,
  craneLib,
  darwin,
  lib,
  libclang,
  libiconv,
  src,
  stdenv,
  ## Whether to use exactly the dependency versions specified in the Cargo.lock file.
  locked ? true,
}:
craneLib.buildPackage {
  inherit cargoArtifacts src;

  strictDeps = true;

  buildInputs = lib.optionals stdenv.hostPlatform.isDarwin [
    darwin.apple_sdk.frameworks.Security
    libiconv
  ];

  LIBCLANG_PATH = libclang.lib + "/lib";

  cargoExtraArgs = lib.concatStringsSep " " (lib.optional locked "--locked");

  doCheck = true;

  doInstallCheck = true;
}
