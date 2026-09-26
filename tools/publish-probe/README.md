# pkcs11-components publishing probe

Use this crate to test API-token and trusted publishing on
**staging.crates.io**. It has no dependencies, and its manifest allows
publication only to the staging registry.

The workspace packaging jobs check library archives, dependency resolution and
builds. This crate contains no PKCS#11 code. It tests the upload process because
staging may lack the libraries' dependencies and rejects dependencies from
other registries.

The workflow copies this template to a temporary directory, includes both
project licenses, and assigns `0.0.0-ci.RUN_ID.RUN_ATTEMPT`. The package is only
for publishing tests, not for use by applications.

Licensed under Apache-2.0 OR MIT.
