# Repository guide

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for setup and required checks.

## Compatibility

- Keep Rust 1.88 and edition 2024 compatibility.
- Treat public layouts, field order and offsets, selection results, errors,
  features, reexports, serialized forms, constants, and numeric discriminators
  as semver-significant.
- Keep layout-only `pkcs11-abi` and `pkcs11-module` builds `no_std` and
  dependency-free.
- Do not broaden the documented little-endian Linux LP64/ILP32 target model
  implicitly.

## FFI safety

- Acquisition executes provider code and never calls `C_Initialize`.
- Keep retry/allocation bounds and absent-export versus empty-list errors
  distinct.
- Returned pointers require the provider library to remain loaded.
- Unsafe raw-pointer readers require a valid live table extent; slice readers
  remain bounds-checked.
- `Surface` and `Provenance` contain caller assertions, not authenticated facts.

Keep changes focused on the active task and preserve unrelated work already in
the worktree.
