# Releasing pkcs11-components

All three crates share a version and an annotated `vVERSION` tag. They support
Rust 1.88; packaging and publishing use Cargo 1.98.0. Cargo's
[workspace publishing](https://blog.rust-lang.org/2025/09/18/Rust-1.90.0/)
support checks unpublished workspace dependencies during a dry run and uploads
them in dependency order. An upload can succeed for some crates and fail for
others; see [recovery](#partial-publication-and-recovery) below.

## Required CI

`ci.yml` runs on branch pushes and pull requests. For a release tag,
`publish.yml` calls it on the tagged revision after release checks. The
required `All release gates` check passes only when every CI job succeeds.
A failed, cancelled or skipped job prevents publication.

| Check | Coverage |
| --- | --- |
| Rust 1.88 / x86_64 | Check, unit/integration/example tests, doctests, rustfmt, Clippy, optimized tests |
| Rust 1.88 / i686 | 32-bit Linux tests, native C layouts and `CK_ULONG` sentinel conversions |
| Rust 1.98 / x86_64 | Tests on the pinned release toolchain |
| Layout-only | Separate no-default-feature checks/tests; ABI zero dependencies, module only ABI |
| Documentation | Rustdoc with warnings denied; docs.rs restricted to the documented Linux targets |
| cargo-deny 0.20.2 | Dependency advisories, license allowlist, source restrictions |
| Miri nightly-2026-09-17 | ABI/module tests, native parameter layouts, types width laws and sentinel integration tests |
| Kani 0.68.0 | ABI selection, layout, read bounds and width-conversion properties within the proof harness bounds |
| Packages | Archive contents and manifests; native and no_std consumers built from the archives on Rust 1.88 |
| Release tooling | Python behavior tests and actionlint 1.7.12 |

Miri and Kani check the code covered by their tests and proof harnesses. They
do not run a real provider or establish full PKCS#11 conformance. The optional
provider test is described in [CONTRIBUTING.md](CONTRIBUTING.md).

Actions and verification tools are pinned. Dependabot updates must pass the
same checks before merging.

## Testing publication

[staging.crates.io](https://staging.crates.io) exists, with sparse index
`sparse+https://index.staging.crates.io/`. The official
[authentication action](https://github.com/rust-lang/crates-io-auth-action#using-a-different-registry-url)
supports `url: https://staging.crates.io`.

Staging has its own index and may lack dependencies available on crates.io.
Its [publish endpoint](https://github.com/rust-lang/crates.io/blob/a76a3efa1daf76c3829205bf33b7d420a3ee802b/src/controllers/krate/publish.rs#L883)
rejects dependencies from other registries and unknown dependency names,
including optional and development dependencies. Use the two checks below
instead of copying third-party crates to staging.

1. **Check the real packages without uploading:**

   ```bash
   cargo +1.98.0 publish --workspace --locked --dry-run --registry crates-io
   cargo +1.98.0 package --workspace --locked
   python3 scripts/release_checks.py archives --package-dir target/package
   python3 scripts/release_checks.py consumer --package-dir target/package --toolchain 1.88.0
   ```

   Run from a clean commit. When testing changed sources at the same version,
   pass a fresh `--target-dir` to both Cargo commands and use its `package/`
   directory for the Python checks. This avoids reusing an older package from
   Cargo's temporary registry cache. `cargo package` puts the final archives
   in that directory; a workspace publish dry run can leave them in temporary
   subdirectories. CI saves the archives, inventory and `SHA256SUMS` as artifacts.

2. **Test authentication and upload on staging:** `publish-staging.yml`
   generates a dependency-free
   `pkcs11-components-publish-probe` package at
   `0.0.0-ci.RUN_ID.RUN_ATTEMPT`. `publish = ["staging"]` prevents production
   publication. Changes to the probe or its workflow run a dry run in CI.
   Uploads require a manual workflow run from `main`.

The probe tests registry authentication and upload. The workspace package
checks validate archive contents, dependency resolution and builds. Confirm
that your staging account and its trusted-publisher settings are still
available before using them.

## One-time account and environment setup

Check the repository settings before releasing and create any that are missing.
The [trusted publishing documentation](https://crates.io/docs/trusted-publishing)
currently requires a crate to exist before its owner can configure a trusted
publisher. The first upload therefore needs an API token. Check the registry's
current requirements before that first upload.

1. Log into crates.io with the intended owner, complete the account and email
   requirements, and check that all three names are available. Names are only
   registered when the first upload succeeds.
2. In GitHub, protect `main` with the `All release gates` check. Restrict
   creation/update/deletion of `v*` tags to release maintainers.
3. In GitHub **Settings → Environments**, configure `crates-io` and
   `crates-io-staging` to require a maintainer's approval. Allow only `v*` tags
   in `crates-io` and only `main` in `crates-io-staging`. For a repository with
   one maintainer, allow that maintainer to approve their own runs. These rules
   are repository settings; the workflow files do not create them.
4. For each registry's first publish, create a short-lived token with the
   minimum publication permissions for the intended new crate names. Open the
   matching GitHub environment, choose **Add environment secret**, and name it
   `CARGO_REGISTRY_BOOTSTRAP_TOKEN`. Put the staging token in `crates-io-staging`
   and the production token in `crates-io`. Add it before the first `bootstrap`
   run; adding a secret does not start a workflow or publish a package.
5. After the first upload, configure these trust records on the respective
   registry's crate settings page:

   | Crate(s) | Owner/repository | Workflow filename | Environment |
   | --- | --- | --- | --- |
   | Three production crates | `mingulov` / `pkcs11-components` | `publish.yml` | `crates-io` |
   | Staging probe | `mingulov` / `pkcs11-components` | `publish-staging.yml` | `crates-io-staging` |

6. Run the staging workflow in `trusted` mode. Once trusted publishing works,
   revoke the bootstrap token and remove its GitHub secret. Configure a trusted
   publisher for **each** production crate and consider enabling the registry's
   trusted-publishing-only setting.

OIDC permission exists only in publication jobs. Authentication happens after
verification; the official action revokes its temporary token when the job
finishes. Ordinary CI and dry runs require no registry credential.

## Publish the staging test package

Once these workflows are on `main`:

```bash
gh workflow run publish-staging.yml --ref main -f mode=dry-run
# First upload only, after configuring the staging environment/token:
gh workflow run publish-staging.yml --ref main -f mode=bootstrap
# After adding the probe's trusted publisher on staging:
gh workflow run publish-staging.yml --ref main -f mode=trusted
```

Wait for each run to finish. `bootstrap` and `trusted` upload a new probe
version. `dry-run` checks packaging without uploading or requesting an OIDC
token.

## Publish a release

1. Review the changelog, any migration requirements and changes to public APIs.
   Check the status of the proposed external-mu additions. Set
   `[workspace.package].version` and `[workspace.dependencies].pkcs11-abi.version`
   together. Update the lockfile, README version examples and release notes.
   Put the intended publication date on the version's changelog heading.
2. Commit and review the release. Wait for every CI check to pass. Merge the
   reviewed revision to `main`; verify CI there. Inspect the package inventory
   and archive hashes from that revision.
3. Tag the reviewed main commit. For the first candidate:

   ```bash
   git fetch origin main --tags
   git switch main
   git pull --ff-only
   git status --short
   git tag -a v0.2.0 -m 'pkcs11-components 0.2.0'
   git push origin v0.2.0
   ```

   Stop if the tree is dirty or the intended commit differs. Tag pushing runs
   tag checks and all CI without uploading packages.
4. After those checks succeed, start the publication workflow:

   ```bash
   # Initial publication: environment-scoped, short-lived bootstrap token.
   gh workflow run publish.yml --ref v0.2.0 -f mode=bootstrap -f package=workspace
   # Future versions after all three trusted-publisher records exist:
   gh workflow run publish.yml --ref v0.2.1 -f mode=trusted -f package=workspace
   ```

   Run this on the release tag. The workflow checks that the tag and package
   versions match, the checkout is clean, and the tagged commit is on
   `origin/main`. It runs the full CI suite before the publication job.
5. Review the run's results and approve the production environment.
   Cargo publishes ABI before module and handles index visibility; independent
   types may publish between them. The workflow then builds a fresh Rust 1.88
   consumer using exact versions downloaded from production crates.io.
6. Inspect all three crates' version pages, owners, source contents and docs.rs
   builds. Configure trusted publishing after the bootstrap. Publish release
   notes only after registry consumption and documentation succeed.

Merging and pushing a tag do not upload crates or publish release notes.

## Partial publication and recovery

If upload or index polling fails, stop and inspect the registry: an upload may
have succeeded even when the command returned failure. Preserve the exact tag
and release commit. Never force-move the tag or silently accept a preexisting
version's contents.

Check each exact version through `/api/v1/crates/NAME/VERSION` and its sparse
index entry (`https://index.crates.io/pk/cs/NAME`). Compare the registry checksum
to the corresponding archive retained from the release revision. If the
contents/revision are unexpected, investigate and issue a new version; a yank
does not erase or replace an upload.

Resume only the missing package using the same tag and authentication mode:

```bash
gh workflow run publish.yml --ref v0.2.0 -f mode=bootstrap -f package=pkcs11-module
```

The recovery run still checks the tag and runs all CI jobs. ABI must
be present before module. After all three exist, repeat the fresh registry
consumer check (the final step in `publish.yml`) and docs.rs checks. The
automatic consumer step runs for `package=workspace`; recovery requires this
explicit final verification. Revoke bootstrap credentials after completion.
