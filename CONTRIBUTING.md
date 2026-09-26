# Contributing

This workspace requires Rust 1.88 or newer. Install Rust, Cargo, rustfmt, and
Clippy using your preferred Rust toolchain manager, then confirm the active
toolchain:

```bash
rustc --version
cargo --version
```

With mise, use `mise exec -- cargo +1.88.0 ...` to select Rust 1.88 through
rustup. Packaging uses Cargo 1.98.0 for workspace publishing support; the
libraries still support Rust 1.88.

## Required checks

Run these checks from the repository root before submitting a change:

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
env -u PKCS11_MODULE_TEST_3X_MODULE cargo test --locked --workspace --all-targets
env -u PKCS11_MODULE_TEST_3X_MODULE cargo test --locked --workspace --doc
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo check --locked -p pkcs11-abi --no-default-features
cargo test --locked -p pkcs11-abi --no-default-features
cargo check --locked -p pkcs11-module --no-default-features
cargo test --locked -p pkcs11-module --no-default-features
```

The standard suite unsets `PKCS11_MODULE_TEST_3X_MODULE` so it runs without a
locally installed provider. To test acquisition from a real PKCS#11 3.x
provider, set it to the absolute path of that provider's shared library and
run the module tests separately. The path must exist. Loading the library
executes foreign code.

```bash
PKCS11_MODULE_TEST_3X_MODULE=/absolute/path/to/provider.so \
  cargo test --locked -p pkcs11-module real_3x_module_reports_standard_interfaces -- --nocapture
```

The `native` feature is enabled by default for `pkcs11-abi` and
`pkcs11-module`. The no-default-feature checks cover their `no_std` builds:
ABI has no dependencies, and module depends only on ABI.

## Additional checks

Additional verification runs in CI and can be run locally:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --no-deps
cargo deny check
env -u PKCS11_MODULE_TEST_3X_MODULE cargo +nightly-2026-09-17 miri test --locked -p pkcs11-abi -p pkcs11-module --lib --tests
env -u PKCS11_MODULE_TEST_3X_MODULE cargo +nightly-2026-09-17 miri test --locked -p pkcs11-types --lib width::
env -u PKCS11_MODULE_TEST_3X_MODULE cargo +nightly-2026-09-17 miri test --locked -p pkcs11-types --test unavailable_information
cargo kani -Z unstable-options --harness-timeout 10m -p pkcs11-abi
cargo kani -Z unstable-options --harness-timeout 10m -p pkcs11-types
```

Kani (pinned to 0.68.0 in CI) needs a one-time setup:
`cargo install --locked kani-verifier --version 0.68.0 && cargo kani setup`.
Proof harnesses are in `crates/abi/src/proofs.rs` and
`crates/types/src/proofs.rs`, compiled only under `--cfg kani`. Do not add a
`kani` dependency to any manifest: `cargo kani` injects the verifier library
as a sysroot crate, and an explicit dependency shadows it with the empty
crates.io placeholder.

CI also executes the native tests on `i686-unknown-linux-gnu`, which requires
the Rust target and a 32-bit linker/runtime (`gcc-multilib` and
`libc6-dev-i386` on Ubuntu). This checks native ILP32 layouts and sentinel
conversion, alongside x86_64 LP64. Optimized tests run on Rust 1.88;
Rust 1.98.0 tests detect compatibility drift. The no-default-feature job
asserts ABI has no dependencies and module has only its ABI dependency.

Miri runs the ABI/module tests and types width tests without loading a real
provider. Kani checks layout, selection and width properties within each
harness's bounds. These checks do not establish full PKCS#11 conformance.
`cargo-deny` 0.20.2 checks dependency advisories, licenses and sources.

## Package checks

Cargo's workspace dry run checks all three packages, including the module's
dependency on an unpublished ABI version. Run from a clean commit:

```bash
cargo +1.98.0 publish --workspace --locked --dry-run --registry crates-io
cargo +1.98.0 package --workspace --locked
python3 scripts/release_checks.py archives --package-dir target/package
python3 scripts/release_checks.py consumer --package-dir target/package --toolchain 1.88.0
python3 -m unittest discover -s scripts/tests -v
```

Use a fresh `--target-dir` when repackaging changed sources at the same
unpublished version: Cargo's temporary registry can otherwise reuse the
previous ABI package in its registry cache. Pass that directory's `package/`
to both Python commands. CI starts with a fresh checkout and build directory.

The Python checks inspect archive contents, normalized manifests, dependencies,
features, licenses and embedded data. They also build small native and
layout-only projects against the unpacked crates. Each crate's manifest lists
the files to include, so development tools stay out of published packages.

See [RELEASE.md](RELEASE.md) for staging tests, account setup, trusted
publishing, tags and recovery after a partial upload.

## Documentation

Write documentation for someone using these crates on their own. Explain
safety requirements in rustdoc next to the affected API. Keep local planning
notes and work logs outside the repository.
