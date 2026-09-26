# Changelog

The three crates are versioned together. Public constants, serialized forms,
errors, layouts, selection results, and features are semver-significant.

## [0.2.0] - 2026-09-26

First crates.io release candidate.

### Crates

- `pkcs11-abi`: function-table catalogs, little-endian Linux LP64/ILP32 layouts,
  version/provenance selection, checked readers, and optional native tables.
- `pkcs11-module`: raw pre-initialization provider acquisition and ABI reexports.
  Acquisition does not call `C_Initialize`.
- `pkcs11-types`: owned identifiers, metadata, parameter models, mechanism
  configuration, width conversion, and caller input/output shapes.

### Changes for existing Git users

- `translate_ulong_len` now returns `Result<u64, WidthError>`. Handle
  `UnsupportedWidth` and `Overflow`; arithmetic no longer divides by zero,
  panics on overflow, or wraps. Native unavailable lengths must first be
  canonicalized; `~0UL` remains all ones at the destination width.
- `CkAttributeType::UNIQUE_ID` is `0x04`, replacing the incorrect `0x2e`.
  `LOCAL.is_bool()` now returns true.
- Correct 22 key-type values: `SHA512_224`/`SHA512_256` denote the HMAC
  identifiers `0x43`/`0x44`; `SEED` through `HKDF` use their standard values
  `0x2f` through `0x42`. Public Rust names are retained. Persisted identifiers
  from the initial Git revision may need migration; numeric values cannot
  identify whether a caller used an erroneous constant or the real standard
  mechanism/key type occupying that value.
- GOST derivation uses mechanism `0x1204`, not signing mechanism `0x1201`.
  RC5 ECB/MAC use `rc5`, CBC/CBC_PAD use `rc5_cbc`, and MAC_GENERAL uses
  `rc5_mac_general`. SSL3 MD5/SHA1 MAC use `mac_general`.
- Remove false parameterless registrations for SSL3/TLS premaster generation
  (`0x0370`, `0x0374`) and DSA generators (`0x2003`–`0x2005`), whose required
  parameter structures are not modeled. Filtered discovery excludes them
  unless caller configuration supplies a shape. Transparent discovery and
  `check_operation`'s representability policy are unchanged.

### Additions

- Corrected native `CK_X9_42_MQV_DERIVE_PARAMS` with `pOtherInfo`,
  `pPublicData`, and `pPublicData2`, available through ABI/module `params` and
  root exports under the existing `native` feature. Its layout matches the
  older native binding; it is a distinct Rust type with corrected names.
- Native `CK_MU_GEN_PARAMS`, pointer aliases, and
  `CKM_ML_DSA_EXTERNAL_MU_GEN` (`0x403b`) / `CKM_ML_DSA_EXTERNAL_MU` (`0x403c`).
  The existing owned `MuGenParams` now has matching named mechanism constants
  and default registry metadata. These are **proposed PKCS#11 3.3** additions.
- Per-crate documentation and licenses, explicit package file lists, LP64/ILP32
  tests, Miri, Kani proofs, dependency checks, package verification, staging
  publishing tests and a release workflow with environment approval.

## [0.1.0]

Initial version.
