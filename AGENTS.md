# Agent guide

Read [CONTRIBUTING.md](CONTRIBUTING.md) for setup and checks, and
[RELEASE.md](RELEASE.md) when changing packaging or release workflows.

## Working in this repository

- Inspect the working tree before editing. Preserve unrelated changes and
  keep each change focused on the requested task.
- Read the affected implementation and tests before changing a public contract.
  Add a regression test for a behavior fix; documentation-only edits do not
  need new tests.
- Keep documentation useful to crate users and contributors. Explain safety
  requirements next to the API. Keep local plans and work logs outside the
  repository.

## Crate boundaries

- `pkcs11-abi` defines function-table catalogs, layouts, selection and readers.
  Its layout-only build is `no_std` and has no dependencies.
- `pkcs11-module` acquires provider interfaces and reexports ABI types. Its
  layout-only build is `no_std` and depends only on `pkcs11-abi`.
- `pkcs11-types` provides owned, width-independent data and registry metadata.
  These values need conversion before use as native C parameters. Registry
  entries describe representations; they do not prove provider support.
- Token, session, login and object lifecycle management belong to callers.

## Compatibility

- Keep Rust 1.88 and edition 2024 compatibility.
- Treat public layouts, field order and offsets, selection results, errors,
  features, reexports, serialized forms, constants, and numeric discriminators
  as semver-significant.
- Do not broaden the documented little-endian Linux LP64/ILP32 target model
  implicitly.
- Check native-width changes on both x86_64 and i686. Keep
  `CK_UNAVAILABLE_INFORMATION` as all ones at the native `CK_ULONG` width and
  canonicalize it before cross-width length conversion.
- Keep external-mu additions labeled as proposed in documentation.

## FFI safety

- Acquisition executes provider code and never calls `C_Initialize`.
- Keep interface enumeration retries and allocations bounded. Distinguish a
  missing export from an exported function that returns an empty list.
- Returned pointers require the provider library to remain loaded.
- Unsafe raw-pointer readers require a valid live table extent; slice readers
  remain bounds-checked.
- Native parameter structs borrow their buffers. Copying a struct does not
  copy its pointees, and zero/null defaults do not establish valid parameters.
- `Surface` and `Provenance` contain caller assertions, not authenticated facts.

## Verification and releases

- Run the required checks in `CONTRIBUTING.md` before committing. Use the
  pinned toolchains and tools from CI for additional checks relevant to the
  change. With mise, invoke Rust tools through `mise exec --`.
- Report which checks ran and any failures or checks left unrun. Miri and Kani
  cover selected tests and harness bounds; they do not establish full provider
  correctness or PKCS#11 conformance.
- Keep the three crate versions synchronized. Review packaged files, manifests
  and unpacked consumers when changing package contents or dependencies.
- Preserve release guards, environment restrictions and secret handling. A
  successful dry run does not demonstrate a credentialed upload. Follow the
  documented bootstrap, trusted-publishing and partial-release recovery steps.
- Obtain explicit authorization before publishing packages or rewriting remote
  history. Existing authorization for the current task remains valid.
