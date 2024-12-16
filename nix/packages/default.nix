{
  callPackage,
  craneLib,
  src,
}: let
  dependencies = callPackage ./dependencies.nix {inherit craneLib src;};
in {
  zcash_script = callPackage ./zcash_script {inherit craneLib src;
    cargoArtifacts = dependencies;};
  zcash_script-dependencies = dependencies;
}
