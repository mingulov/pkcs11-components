import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "release_checks.py"


def load_checks():
    spec = importlib.util.spec_from_file_location("release_checks", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, text=True,
                          capture_output=True).stdout.strip()


class ReleaseChecksTests(unittest.TestCase):
    def setUp(self):
        # The fixture is its own tagged checkout, independent of the CI event.
        event = mock.patch.dict(os.environ, {"GITHUB_REF": "refs/tags/v0.2.0"})
        event.start()
        self.addCleanup(event.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()
        (self.repo / "Cargo.toml").write_text(
            '[workspace]\nresolver = "2"\nmembers = ["crates/abi", "crates/module", "crates/types"]\n'
            '[workspace.package]\nversion = "0.2.0"\nedition = "2024"\nrust-version = "1.88"\n'
            'license = "Apache-2.0 OR MIT"\nrepository = "https://example.invalid/repo"\n'
            '[workspace.dependencies]\npkcs11-abi = { path = "crates/abi", version = "0.2.0", default-features = false }\n'
        )
        for directory, name in [("abi", "pkcs11-abi"), ("module", "pkcs11-module"),
                                ("types", "pkcs11-types")]:
            root = self.repo / "crates" / directory
            (root / "src").mkdir(parents=True)
            manifest = (f'[package]\nname = "{name}"\nversion.workspace = true\n'
                        'edition.workspace = true\nrust-version.workspace = true\n'
                        'license.workspace = true\nrepository.workspace = true\n')
            manifest += f'description = "{name} description"\nreadme = "README.md"\n'
            if directory == "module":
                manifest += '[dependencies]\npkcs11-abi = { workspace = true }\n'
            (root / "Cargo.toml").write_text(manifest)
            (root / "src" / "lib.rs").write_text(f"// {name}\n")
            for filename in ("README.md", "LICENSE-APACHE", "LICENSE-MIT"):
                (root / filename).write_text(f"{name} {filename}\n")
        data = self.repo / "crates" / "types" / "src" / "mechanism_params_default.toml"
        data.write_text('name = "embedded"\n')
        git(self.repo, "init", "-q")
        git(self.repo, "add", ".")
        git(self.repo, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
            "commit", "-qm", "fixture")
        git(self.repo, "tag", "v0.2.0")
        self.checks = load_checks()

    def archive(self, name, directory, *, omit=(), extra=None):
        package_dir = self.repo / "target" / "package"
        package_dir.mkdir(parents=True, exist_ok=True)
        root = self.repo / "crates" / directory
        entries = {}
        for source in root.rglob("*"):
            if source.is_file() and source.relative_to(root).as_posix() not in omit:
                entries[source.relative_to(root).as_posix()] = source.read_bytes()
        entries.pop("Cargo.toml", None)
        entries["Cargo.toml.orig"] = (root / "Cargo.toml").read_bytes()
        entries["Cargo.toml"] = (
            f'[package]\nname = "{name}"\nversion = "0.2.0"\nedition = "2024"\n'
            'rust-version = "1.88"\nlicense = "Apache-2.0 OR MIT"\n'
            f'readme = "README.md"\ndescription = "{name} description"\n'
            'repository = "https://example.invalid/repo"\n'
            + ('[dependencies]\npkcs11-abi = { version = "0.2.0" }\n' if directory == "module" else '')
        ).encode()
        if extra is not None:
            entries[extra[0]] = extra[1]
        if directory == "module" and extra is None:
            entries["Cargo.toml"] = entries["Cargo.toml"].replace(
                b'pkcs11-abi = { version = "0.2.0" }',
                b'pkcs11-abi = { version = "0.2.0", default-features = false }')
        archive = package_dir / f"{name}-0.2.0.crate"
        with tarfile.open(archive, "w:gz") as out:
            for path, payload in entries.items():
                info = tarfile.TarInfo(f"{name}-0.2.0/{path}")
                info.size = len(payload)
                out.addfile(info, io.BytesIO(payload))
        return package_dir

    def all_archives(self):
        for directory, name in [("abi", "pkcs11-abi"), ("module", "pkcs11-module"),
                                ("types", "pkcs11-types")]:
            self.archive(name, directory)
        return self.repo / "target" / "package"

    def test_preflight_rejects_branch_and_malformed_tags(self):
        for ref in ("main", "refs/heads/main", "refs/tags/v01.2.3", "refs/tags/v0.2.0+meta",
                    "refs/tags/v0.2.0-01", "refs/tags/v0.2"):
            with self.subTest(ref=ref), self.assertRaises(self.checks.ReleaseError):
                self.checks.preflight(self.repo, ref)

    def test_preflight_accepts_clean_matching_tag_and_checks_main(self):
        self.checks.preflight(self.repo, "refs/tags/v0.2.0")
        with self.assertRaises(self.checks.ReleaseError):
            self.checks.preflight(self.repo, "refs/tags/v0.2.0", require_main=True)
        git(self.repo, "update-ref", "refs/remotes/origin/main", "HEAD")
        self.checks.preflight(self.repo, "refs/tags/v0.2.0", require_main=True)

    def test_preflight_rejects_branch_dispatch_even_with_tag_argument(self):
        with mock.patch.dict(os.environ, {"GITHUB_REF": "refs/heads/main"}):
            with self.assertRaises(self.checks.ReleaseError):
                self.checks.preflight(self.repo, "refs/tags/v0.2.0")

    def test_preflight_rejects_dirty_tree_and_dependency_version_drift(self):
        (self.repo / "dirty").write_text("x")
        with self.assertRaises(self.checks.ReleaseError):
            self.checks.preflight(self.repo, "refs/tags/v0.2.0")
        (self.repo / "dirty").unlink()
        manifest = self.repo / "Cargo.toml"
        manifest.write_text(manifest.read_text().replace('version = "0.2.0", default-features',
                                                         'version = "0.3.0", default-features'))
        with self.assertRaises(self.checks.ReleaseError):
            self.checks.preflight(self.repo, "refs/tags/v0.2.0")

    def test_archives_emit_inventory_and_checksums(self):
        package_dir = self.all_archives()
        inventory = self.checks.inspect_archives(self.repo, package_dir, write=True)
        self.assertEqual([item["name"] for item in inventory["packages"]],
                         ["pkcs11-abi", "pkcs11-module", "pkcs11-types"])
        self.assertEqual(len((package_dir / "SHA256SUMS").read_text().splitlines()), 3)
        self.assertEqual(len(json.loads((package_dir / "package-inventory.json").read_text())
                             ["packages"]), 3)

    def test_archives_reject_missing_embedded_data(self):
        package_dir = self.all_archives()
        self.archive("pkcs11-types", "types", omit=("src/mechanism_params_default.toml",))
        with self.assertRaises(self.checks.ReleaseError):
            self.checks.inspect_archives(self.repo, package_dir)

    def test_archives_reject_traversal_and_private_files(self):
        package_dir = self.all_archives()
        for injected in ("../evil", "src/.secret", "private.key"):
            with self.subTest(path=injected):
                self.archive("pkcs11-abi", "abi", extra=(injected, b"secret"))
                with self.assertRaises(self.checks.ReleaseError):
                    self.checks.inspect_archives(self.repo, package_dir)

    def test_archives_reject_normalized_feature_drift(self):
        package_dir = self.all_archives()
        normalized = (
            '[package]\nname = "pkcs11-abi"\nversion = "0.2.0"\nedition = "2024"\n'
            'rust-version = "1.88"\nlicense = "Apache-2.0 OR MIT"\n'
            'readme = "README.md"\n[features]\ndefault = ["native"]\n'
        ).encode()
        self.archive("pkcs11-abi", "abi", extra=("Cargo.toml", normalized))
        with self.assertRaises(self.checks.ReleaseError):
            self.checks.inspect_archives(self.repo, package_dir)

    def test_archives_reject_normalized_metadata_and_dependency_drift(self):
        package_dir = self.all_archives()
        wrong = (
            '[package]\nname = "pkcs11-types"\nversion = "0.2.0"\nedition = "2024"\n'
            'rust-version = "1.88"\nlicense = "Apache-2.0 OR MIT"\n'
            'readme = "README.md"\ndescription = "tampered"\n'
            '[dependencies]\nserde = "1"\n'
        ).encode()
        self.archive("pkcs11-types", "types", extra=("Cargo.toml", wrong))
        with self.assertRaises(self.checks.ReleaseError):
            self.checks.inspect_archives(self.repo, package_dir)

    def test_archives_reject_dependency_feature_drift(self):
        package_dir = self.all_archives()
        normalized = (
            '[package]\nname = "pkcs11-module"\nversion = "0.2.0"\nedition = "2024"\n'
            'rust-version = "1.88"\nlicense = "Apache-2.0 OR MIT"\n'
            'readme = "README.md"\ndescription = "pkcs11-module description"\n'
            'repository = "https://example.invalid/repo"\n'
            '[dependencies]\npkcs11-abi = { version = "0.2.0" }\n'
        ).encode()
        self.archive("pkcs11-module", "module", extra=("Cargo.toml", normalized))
        with self.assertRaises(self.checks.ReleaseError):
            self.checks.inspect_archives(self.repo, package_dir)

    def test_consumer_uses_separate_feature_sets_from_unpacked_archives(self):
        package_dir = self.all_archives()
        seen = set()

        def fake_cargo(command, **_kwargs):
            manifest = Path(command[command.index("--manifest-path") + 1])
            content = manifest.read_text()
            if "release-native-consumer" in content:
                self.assertIn("pkcs11-types =", content)
                self.assertIn("[patch.crates-io]", content)
                seen.add("native")
                return subprocess.CompletedProcess(command, 0, "", "")
            self.assertIn("default-features = false", content)
            self.assertNotIn("pkcs11-types =", content)
            seen.add("layout-only")
            if "tree" in command:
                output = ("release-layout-consumer v0.0.0\n"
                          "pkcs11-abi v0.2.0\n"
                          "pkcs11-module v0.2.0\n") if "--prefix" in command and command[command.index("--prefix") + 1] == "none" else (
                          "release-layout-consumer v0.0.0\n"
                          "├── pkcs11-abi v0.2.0\n"
                          "└── pkcs11-module v0.2.0\n")
                return subprocess.CompletedProcess(command, 0, output, "")
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(self.checks.subprocess, "run", side_effect=fake_cargo):
            self.checks.consumer(self.repo, package_dir, "1.88.0")
        self.assertEqual(seen, {"native", "layout-only"})

    def test_probe_replaces_version_and_stays_staging_only(self):
        template = self.repo / "tools" / "publish-probe"
        (template / "src").mkdir(parents=True)
        (template / "Cargo.toml").write_text(
            '[package]\nname = "probe-test"\nversion = "0.0.0"\n'
            'publish = ["staging"]\nlicense = "Apache-2.0 OR MIT"\n[workspace]\n'
        )
        (template / "src" / "lib.rs").write_text("// probe\n")
        for license_file in ("LICENSE-APACHE", "LICENSE-MIT"):
            (self.repo / license_file).write_text("license\n")
        destination = Path(self.tmp.name) / "prepared"
        self.checks.prepare_probe(self.repo, destination, "17", "3")
        content = (destination / "Cargo.toml").read_text()
        self.assertIn('version = "0.0.0-ci.17.3"', content)
        self.assertIn('publish = ["staging"]', content)
        self.assertTrue((destination / "LICENSE-MIT").is_file())
        self.assertTrue((destination / "src" / "lib.rs").is_file())

    def test_probe_rejects_production_or_dependencies(self):
        template = self.repo / "tools" / "publish-probe"
        template.mkdir(parents=True)
        manifest = template / "Cargo.toml"
        for suffix in ('publish = ["crates-io"]\n',
                       'publish = ["staging"]\n[dependencies]\nserde = "1"\n'):
            with self.subTest(suffix=suffix):
                manifest.write_text('[package]\nname = "probe-test"\nversion = "0.0.0"\n'
                                    + suffix + '[workspace]\n')
                with self.assertRaises(self.checks.ReleaseError):
                    self.checks.prepare_probe(self.repo, Path(self.tmp.name) / "prepared", "17", "3")
        with self.assertRaises(self.checks.ReleaseError):
            self.checks.prepare_probe(self.repo, Path(self.tmp.name) / "prepared", "1x", "3")


if __name__ == "__main__":
    unittest.main()
