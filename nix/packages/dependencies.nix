{
  craneLib,
  lib,
  libclang,
  libiconv,
  src,
  stdenv,
}:
craneLib.buildDepsOnly {
  inherit src;

  buildInputs = lib.optional stdenv.hostPlatform.isDarwin libiconv;
}
