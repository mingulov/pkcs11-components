# Contributing

This workspace requires Rust 1.88 or newer. Install Rust, Cargo, rustfmt, and
Clippy using your preferred Rust toolchain manager, then confirm the active
toolchain:

```bash
rustc --version
cargo --version
```

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

The environment variable is unset in the standard suite so results do not
depend on a locally installed provider. To opt into the real-provider PKCS#11
3.x acquisition test, set `PKCS11_MODULE_TEST_3X_MODULE` to the absolute path of
a provider shared library and run the `pkcs11-module` tests separately. Loading
that library executes foreign code.

```bash
PKCS11_MODULE_TEST_3X_MODULE=/absolute/path/to/provider.so \
  cargo test --locked -p pkcs11-module real_3x_module_reports_standard_interfaces -- --nocapture
```

The `native` feature is enabled by default for `pkcs11-abi` and
`pkcs11-module`. Always retain the no-default-feature checks: they protect the
dependency-free `no_std` layout facade.

Documentation changes should remain understandable without unpublished design
records or knowledge of another application. Public safety contracts belong in
rustdoc near the affected API.
