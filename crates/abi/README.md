# pkcs11-abi

Inspect PKCS#11 function tables on little-endian Linux LP64 and ILP32 systems.
This crate provides field catalogs, C layout offsets, version-aware prefix
selection and bounds-checked readers. It is part of
[pkcs11-components](https://github.com/mingulov/pkcs11-components).

```toml
[dependencies]
pkcs11-abi = "0.2"
```

```rust
use pkcs11_abi::{LinuxLayout, function_name, table_bytes};

let bytes = table_bytes(LinuxLayout::Ilp32, 104).expect("known PKCS#11 prefix");
assert_eq!(bytes, 420);
assert_eq!(function_name(103), Some("C_UnwrapKeyAuthenticated"));
```

## Features

The default `native` feature adds `cryptoki-sys` and native-layout tables.
It also exposes `params`: the corrected `CK_X9_42_MQV_DERIVE_PARAMS` with
`pOtherInfo`, `pPublicData`, and `pPublicData2`, plus `CK_MU_GEN_PARAMS` and
the external-mu identifiers proposed for PKCS#11 3.3.
The external-mu additions are **proposed**. Keep buffers referenced by native
parameter pointers alive while the provider uses them. `Default` fills fields
with zeros and null pointers; check the provider's requirements before making
a call.
Without default features the crate is a dependency-free `no_std` library with
target-layout facts and slice readers:

```toml
[dependencies]
pkcs11-abi = { version = "0.2", default-features = false }
```

See the [workspace README](https://github.com/mingulov/pkcs11-components)
for usage, safety requirements and versioning.

## License

Licensed under either [Apache License 2.0](LICENSE-APACHE) or the
[MIT License](LICENSE-MIT), at your option.
