# Verify `no_std` support

This library exists to ensure that zcash_script builds without `std`.

(Include some reference to the problems)

This is referenced by [GitHub CI](../.github/workflows/ci.yml), but to test it yourself, run

```bash
cargo build --verbose --target thumbv7em-none-eabihf
```

in this directory. The target is the important thing, as that target doesn’t support `std`, so anything that causes it to be enabled will fail.

This is done in a separate library (rather than simply building `zcash_script` on that particular target) to ensure that no `dev_dependencies` (which do not need to work under `no_std`) are included in the build.
