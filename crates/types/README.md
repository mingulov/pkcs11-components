# pkcs11-types

Owned PKCS#11 identifiers, mechanism parameters, registry settings, and
operation inputs and outputs.

Identifiers and handles use width-independent `u64` values; other data uses
owned Rust types. Convert these values to native C types before passing them
to a PKCS#11 provider. This crate is part of the
[pkcs11-components](https://github.com/mingulov/pkcs11-components) workspace
and requires `std`.

```toml
[dependencies]
pkcs11-types = "0.2"
```

```rust
use pkcs11_types::{CkMechanismType, MechanismRegistry};

let registry = MechanismRegistry::load(None).expect("embedded registry should parse");
assert_eq!(registry.param_shape(CkMechanismType::AES_GCM.0), Some("gcm"));
```

The shape name describes how this crate represents parameters. Check the
provider separately for mechanism support.

The owned `MuGenParams` and external-mu mechanism identifiers (`0x403b` and
`0x403c`) are proposed PKCS#11 3.3 additions.

For `CK_UNAVAILABLE_INFORMATION`, canonicalize the native `~0UL` value before
cross-width length conversion. Its native value is `0xffffffff` on ILP32 and
`0xffffffffffffffff` on LP64; the width-independent canonical form is `u64::MAX`.

See the [workspace README](https://github.com/mingulov/pkcs11-components)
for usage, safety requirements and versioning.

## License

Licensed under either [Apache License 2.0](LICENSE-APACHE) or the
[MIT License](LICENSE-MIT), at your option.
