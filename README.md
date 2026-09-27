# pkcs11-components

Rust libraries for inspecting PKCS#11 function tables, acquiring provider
interfaces, and storing or exchanging PKCS#11 data.

Applications remain responsible for tokens, sessions, login and object
operations.

## Crates

| Crate | Use it when you need |
| --- | --- |
| [`pkcs11-abi`](crates/abi) | Function-table field catalogs, Linux LP64/ILP32 offsets, version-aware prefix selection, or bounds-checked table readers |
| [`pkcs11-module`](crates/module) | Raw `C_GetFunctionList` and `C_GetInterfaceList` acquisition from a shared library, before initialization |
| [`pkcs11-types`](crates/types) | Owned identifiers, mechanism parameters, registry settings, and operation inputs and outputs |

`pkcs11-abi` models C layouts. `pkcs11-types` uses owned Rust values, mostly
based on `u64`, for storage, transport and conversion between native widths.
Convert these values to native C types before passing them to a provider.

## Requirements

- Rust 1.88 or newer
- A little-endian Linux target for the explicitly modeled LP64 and ILP32 layouts
- A provider shared library only when using `pkcs11-module` acquisition

The first crates.io release is being prepared. After publication, add:

```toml
[dependencies]
pkcs11-abi = "0.2"
pkcs11-module = "0.2"
pkcs11-types = "0.2"
libloading = "0.9" # needed when your code opens provider libraries
```

Until publication, or to select an exact source revision, pin a Git commit:

```toml
[dependencies]
pkcs11-abi = { git = "https://github.com/mingulov/pkcs11-components", rev = "<commit>" }
pkcs11-module = { git = "https://github.com/mingulov/pkcs11-components", rev = "<commit>" }
pkcs11-types = { git = "https://github.com/mingulov/pkcs11-components", rev = "<commit>" }
```

For a local checkout, replace `git` and `rev` with a `path` such as
`path = "../pkcs11-components/crates/abi"`.

## Usage

Inspect the byte size and final field of the PKCS#11 3.2 function-table prefix
for a 32-bit Linux target:

```rust
use pkcs11_abi::{LinuxLayout, function_name, table_bytes};

let bytes = table_bytes(LinuxLayout::Ilp32, 104).expect("known PKCS#11 prefix");
assert_eq!(bytes, 420);
assert_eq!(function_name(103), Some("C_UnwrapKeyAuthenticated"));
```

Load a provider and acquire its legacy function list without initializing it:

```rust,no_run
let library = unsafe { libloading::Library::new("/path/to/provider.so") }
    .expect("trusted provider should load");
let table = pkcs11_module::function_list(&library)
    .expect("provider should export a valid C_GetFunctionList");
println!("legacy function table: {table:p}");
```

Loading a shared library executes foreign initialization code. Keep `library`
alive for as long as any returned pointer may be used.

Look up the parameter representation registered for a mechanism:

```rust
use pkcs11_types::{CkMechanismType, MechanismRegistry};

let registry = MechanismRegistry::load(None).expect("embedded registry should parse");
assert_eq!(registry.param_shape(CkMechanismType::AES_GCM.0), Some("gcm"));
```

The shape name describes how this crate represents parameters. Check the
provider separately for mechanism support.

Runnable versions are available in
[`crates/abi/examples/layout.rs`](crates/abi/examples/layout.rs),
[`crates/module/examples/inspect.rs`](crates/module/examples/inspect.rs), and
[`crates/types/examples/mechanisms.rs`](crates/types/examples/mechanisms.rs).

```bash
cargo run -p pkcs11-abi --no-default-features --example layout
cargo run -p pkcs11-types --example mechanisms
cargo run -p pkcs11-module --example inspect -- /absolute/path/to/provider.so
```

## Features and dependencies

`pkcs11-abi` enables `native` by default. The feature adds `cryptoki-sys` and
native-layout tables; disabling default features leaves a dependency-free
`no_std` crate containing target-layout facts and slice readers.

`pkcs11-module` also enables `native` by default. Without it, the crate is a
`no_std` wrapper around `pkcs11-abi` with no other dependencies. Provider
acquisition requires `native`.

`pkcs11-types` requires `std` and has no optional features. Cargo feature
unification may enable `pkcs11-abi/native` when another dependency requests it.

## Safety and limits

- The explicit target model is little-endian Linux LP64/ILP32. Native tables
  follow the compilation target's `cryptoki-sys` bindings.
- Slice readers validate offsets and lengths. `detect_null_functions` is unsafe
  and requires a valid, live function-table extent of the matching native type.
- Module acquisition calls exported provider functions but never calls
  `C_Initialize`.
- Returned provider pointers remain valid only as long as the loaded library
  and the provider's own contract permit.
- `Provenance`, `Surface`, and reported versions are caller assertions; the
  types do not authenticate their origin.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and validation commands. Build
the API documentation locally with:

```bash
cargo doc --locked --workspace --no-deps --open
```

See [RELEASE.md](RELEASE.md) for package checks, staging tests, trusted
publishing and the release steps.

## Versioning

The three packages are versioned together. Before 1.0, compatible additions
and fixes increment the patch version, while breaking changes increment the
minor version.

Semver-significant contracts include public layouts, field order and offsets,
known-prefix sizes, selection results, acquisition bounds and error distinctions,
module paths, reexports, features, serialized forms, constants, and numeric
discriminators.

## License

Licensed under either [Apache License 2.0](LICENSE-APACHE) or the
[MIT License](LICENSE-MIT), at your option.
