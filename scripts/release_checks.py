#!/usr/bin/env python3
"""Release-ref, crate archive, consumer, and staging-probe checks."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib


REPO_ROOT = Path(__file__).resolve().parents[1]
CRATES = (("pkcs11-abi", "abi"), ("pkcs11-module", "module"), ("pkcs11-types", "types"))
VERSION = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
IDENTIFIER = r"(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
TAG = re.compile(rf"refs/tags/v(?P<version>{VERSION}(?:-{IDENTIFIER}(?:\.{IDENTIFIER})*)?)\Z")
NUMBER = re.compile(r"(?:0|[1-9][0-9]*)\Z")
MAX_MEMBER = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024


class ReleaseError(Exception):
    """A package or release check failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def parse_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseError(f"cannot read TOML {path}: {exc}") from exc


def workspace_version(repo: Path) -> str:
    workspace = parse_toml(repo / "Cargo.toml")
    version = workspace.get("workspace", {}).get("package", {}).get("version")
    require(isinstance(version, str), "workspace package version is missing")
    return version


def crate_manifest(repo: Path, directory: str) -> dict:
    return parse_toml(repo / "crates" / directory / "Cargo.toml")


def effective_version(manifest: dict, workspace: str) -> str:
    value = manifest.get("package", {}).get("version")
    if isinstance(value, str):
        return value
    if isinstance(value, dict) and value.get("workspace") is True:
        return workspace
    raise ReleaseError("crate package version is missing or invalid")


def checked_workspace(repo: Path) -> str:
    version = workspace_version(repo)
    require(bool(re.fullmatch(rf"{VERSION}(?:-{IDENTIFIER}(?:\.{IDENTIFIER})*)?", version)),
            f"invalid workspace version {version!r}")
    for name, directory in CRATES:
        manifest = crate_manifest(repo, directory)
        require(manifest.get("package", {}).get("name") == name,
                f"{directory} package name is not {name}")
        require(effective_version(manifest, version) == version,
                f"{name} version is not {version}")
    workspace = parse_toml(repo / "Cargo.toml")
    abi_dep = workspace.get("workspace", {}).get("dependencies", {}).get("pkcs11-abi")
    require(isinstance(abi_dep, dict) and abi_dep.get("version") == version,
            f"workspace pkcs11-abi dependency must require {version}")
    module_dep = crate_manifest(repo, "module").get("dependencies", {}).get("pkcs11-abi")
    require(isinstance(module_dep, dict) and module_dep.get("workspace") is True,
            "pkcs11-module must inherit the synchronized pkcs11-abi dependency")
    return version


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True)
    if result.returncode:
        raise ReleaseError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def preflight(repo: Path, ref: str, require_main: bool = False) -> str:
    match = TAG.fullmatch(ref)
    require(match is not None, "release ref must be refs/tags/vVERSION (stable or prerelease)")
    event_ref = os.environ.get("GITHUB_REF")
    require(not event_ref or event_ref == ref,
            f"GitHub event ref {event_ref!r} differs from requested release tag {ref!r}")
    version = checked_workspace(repo)
    require(match.group("version") == version, f"tag version {match.group('version')} != {version}")
    git(repo, "show-ref", "--verify", "--quiet", ref)
    tagged = git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}")
    head = git(repo, "rev-parse", "HEAD")
    require(tagged == head, f"{ref} points to {tagged}, not HEAD {head}")
    require(not git(repo, "status", "--porcelain", "--untracked-files=all"),
            "release checkout has tracked or untracked changes")
    if require_main:
        git(repo, "rev-parse", "--verify", "origin/main^{commit}")
        git(repo, "merge-base", "--is-ancestor", "HEAD", "origin/main")
    return version


def allowed_member(path: str) -> bool:
    if path in {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json",
                "README.md", "LICENSE-APACHE", "LICENSE-MIT"}:
        return True
    parts = path.split("/")
    return len(parts) > 1 and parts[0] in {"src", "tests", "examples"} and all(
        part and part not in {".", ".."} and not part.startswith(".") for part in parts[1:]
    )


def archive_entries(archive: Path, name: str, version: str) -> dict[str, bytes]:
    prefix = f"{name}-{version}"
    entries: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(archive, "r:gz") as package:
            for member in package:
                raw = member.name
                require("\\" not in raw and not raw.startswith("/"), f"unsafe archive path {raw!r}")
                segments = raw.rstrip("/").split("/")
                require(all(segment not in {"", ".", ".."} for segment in segments),
                        f"unsafe archive path {raw!r}")
                require(segments[0] == prefix, f"archive entry outside {prefix}: {raw}")
                if member.isdir():
                    continue
                require(member.isfile(), f"archive link or special file forbidden: {raw}")
                require(len(segments) >= 2, f"archive file has no relative path: {raw}")
                relative = "/".join(segments[1:])
                require(allowed_member(relative), f"unexpected or private archive file: {relative}")
                require(relative not in entries, f"duplicate archive file: {relative}")
                require(member.size <= MAX_MEMBER, f"archive file too large: {relative}")
                total += member.size
                require(total <= MAX_TOTAL and len(entries) < 1000, "archive exceeds safety limits")
                stream = package.extractfile(member)
                require(stream is not None, f"cannot read archive file: {relative}")
                data = stream.read(MAX_MEMBER + 1)
                require(len(data) == member.size, f"archive file length mismatch: {relative}")
                entries[relative] = data
    except (OSError, tarfile.TarError) as exc:
        raise ReleaseError(f"cannot inspect {archive}: {exc}") from exc
    return entries


def expected_source_files(root: Path) -> dict[str, bytes]:
    expected = {}
    for fixed in ("README.md", "LICENSE-APACHE", "LICENSE-MIT"):
        path = root / fixed
        require(path.is_file() and not path.is_symlink(), f"missing package source {path}")
        expected[fixed] = path.read_bytes()
    for section in ("src", "tests", "examples"):
        folder = root / section
        if folder.exists():
            for path in folder.rglob("*"):
                if path.is_file():
                    require(not path.is_symlink(), f"source symlink forbidden: {path}")
                    relative = path.relative_to(root).as_posix()
                    require(allowed_member(relative), f"unexpected package source: {relative}")
                    expected[relative] = path.read_bytes()
    require("src/lib.rs" in expected, f"missing package source {root / 'src/lib.rs'}")
    return expected


def inherited_package_value(source: dict, workspace: dict, key: str) -> object:
    value = source.get("package", {}).get(key)
    if isinstance(value, dict) and value.get("workspace") is True:
        return workspace.get("workspace", {}).get("package", {}).get(key)
    return value


def dependency_version(source_dep: object, workspace: dict, key: str) -> str | None:
    if isinstance(source_dep, str):
        return source_dep
    if isinstance(source_dep, dict):
        if source_dep.get("workspace") is True:
            inherited = workspace.get("workspace", {}).get("dependencies", {}).get(key)
            if isinstance(inherited, dict):
                return inherited.get("version")
            if isinstance(inherited, str):
                return inherited
        return source_dep.get("version")
    return None


def dependency_flags(source_dep: object, workspace: dict, key: str) -> tuple[bool, bool, set[str]]:
    details = source_dep if isinstance(source_dep, dict) else {}
    inherited = workspace.get("workspace", {}).get("dependencies", {}).get(key)
    base = inherited if details.get("workspace") is True and isinstance(inherited, dict) else {}
    optional = details.get("optional", base.get("optional", False))
    default_features = details.get("default-features", base.get("default-features", True))
    features = set(base.get("features", [])) | set(details.get("features", []))
    return optional, default_features, features


def validate_archive(repo: Path, package_dir: Path, name: str, directory: str,
                     version: str) -> tuple[dict, dict[str, bytes]]:
    archive = package_dir / f"{name}-{version}.crate"
    require(archive.is_file(), f"missing archive {archive}")
    entries = archive_entries(archive, name, version)
    root = repo / "crates" / directory
    expected = expected_source_files(root)
    for relative, content in expected.items():
        require(relative in entries, f"{name} archive missing {relative}")
        require(entries[relative] == content, f"{name} archive differs from source: {relative}")
    for relative in entries:
        if relative in {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json"}:
            continue
        require(relative in expected, f"{name} archive has unexpected source: {relative}")
    if name == "pkcs11-types":
        require("src/mechanism_params_default.toml" in entries,
                "types archive lacks embedded mechanism data")
    require(entries.get("Cargo.toml.orig") == (root / "Cargo.toml").read_bytes(),
            f"{name} original manifest differs from source")
    try:
        normalized = tomllib.loads(entries["Cargo.toml"].decode("utf-8"))
    except (KeyError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseError(f"{name} normalized Cargo.toml is invalid: {exc}") from exc
    package = normalized.get("package", {})
    require(package.get("name") == name and package.get("version") == version,
            f"{name} normalized package name/version differs")
    require(package.get("edition") == "2024" and package.get("rust-version") in {"1.88", "1.88.0"},
            f"{name} normalized edition or MSRV differs")
    require(package.get("license") == "Apache-2.0 OR MIT" and package.get("readme") == "README.md",
            f"{name} normalized license or readme differs")
    source_manifest = crate_manifest(repo, directory)
    workspace_manifest = parse_toml(repo / "Cargo.toml")
    for key in ("description", "documentation", "repository", "keywords", "categories",
                "edition", "rust-version", "license", "readme"):
        source_value = inherited_package_value(source_manifest, workspace_manifest, key)
        if source_value is not None:
            require(package.get(key) == source_value,
                    f"{name} normalized {key} differs from source")
    source_features = source_manifest.get("features", {})
    require(normalized.get("features", {}) == source_features,
            f"{name} normalized features differ from source")
    for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
        source_deps = source_manifest.get(kind, {})
        archive_deps = normalized.get(kind, {})
        require(set(archive_deps) == set(source_deps),
                f"{name} normalized {kind} names differ from source")
        for dep_name, source_dep in source_deps.items():
            actual = archive_deps[dep_name]
            require(isinstance(actual, dict), f"{name} normalized {dep_name} is not a dependency table")
            expected_version = dependency_version(source_dep, workspace_manifest, dep_name)
            require(expected_version is not None and actual.get("version") == expected_version,
                    f"{name} normalized {dep_name} version differs from source")
            optional, default_features, features = dependency_flags(
                source_dep, workspace_manifest, dep_name)
            require(actual.get("optional", False) == optional
                    and actual.get("default-features", True) == default_features
                    and set(actual.get("features", [])) == features,
                    f"{name} normalized {dep_name} flags differ from source")
    if name == "pkcs11-module":
        abi = normalized.get("dependencies", {}).get("pkcs11-abi")
        require(isinstance(abi, dict) and abi.get("version") == version,
                "module archive has unsynchronized ABI dependency")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return ({"name": name, "version": version, "archive": archive.name, "sha256": digest,
             "files": sorted(entries)}, entries)


def inspect_archives(repo: Path, package_dir: Path, write: bool = False) -> dict:
    version = checked_workspace(repo)
    package_dir = Path(package_dir)
    inventory = {"version": version, "packages": []}
    for name, directory in CRATES:
        record, _ = validate_archive(repo, package_dir, name, directory, version)
        inventory["packages"].append(record)
    if write:
        package_dir.mkdir(parents=True, exist_ok=True)
        (package_dir / "package-inventory.json").write_text(
            json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (package_dir / "SHA256SUMS").write_text(
            "".join(f"{record['sha256']}  {record['archive']}\n" for record in inventory["packages"]),
            encoding="utf-8")
    return inventory


def unpack_verified(repo: Path, package_dir: Path, destination: Path, version: str) -> dict[str, Path]:
    roots = {}
    for name, directory in CRATES:
        _, entries = validate_archive(repo, package_dir, name, directory, version)
        root = destination / f"{name}-{version}"
        for relative, content in entries.items():
            path = root.joinpath(*PurePosixPath(relative).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        roots[name] = root
    return roots


def consumer(repo: Path, package_dir: Path, toolchain: str) -> None:
    require(bool(re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", toolchain)),
            "toolchain must be a numeric Rust version")
    version = inspect_archives(repo, package_dir)["version"]
    with tempfile.TemporaryDirectory(prefix="pkcs11-release-consumer-") as temp:
        base = Path(temp)
        roots = unpack_verified(repo, Path(package_dir), base / "packages", version)
        for mode in ("native", "layout-only"):
            project = base / mode
            (project / "src").mkdir(parents=True)
            abi = json.dumps(str(roots["pkcs11-abi"]))
            module = json.dumps(str(roots["pkcs11-module"]))
            types = json.dumps(str(roots["pkcs11-types"]))
            if mode == "native":
                (project / "Cargo.toml").write_text(
                    f'[package]\nname = "release-native-consumer"\nversion = "0.0.0"\nedition = "2024"\n'
                    f'[dependencies]\npkcs11-abi = {{ path = {abi} }}\n'
                    f'pkcs11-module = {{ path = {module} }}\n'
                    f'pkcs11-types = {{ path = {types} }}\n'
                    f'[patch.crates-io]\npkcs11-abi = {{ path = {abi} }}\n', encoding="utf-8")
                (project / "src" / "lib.rs").write_text(
                    '#[test]\nfn documented_surface() {\n'
                    '    use pkcs11_abi::{LinuxLayout, function_name, table_bytes};\n'
                    '    assert_eq!(table_bytes(LinuxLayout::Ilp32, 104), Ok(420));\n'
                    '    assert_eq!(function_name(103), Some("C_UnwrapKeyAuthenticated"));\n'
                    '    assert_eq!(pkcs11_module::FUNCTION_LIST_FIELDS.len(), 68);\n'
                    '    let registry = pkcs11_types::MechanismRegistry::load(None).unwrap();\n'
                    '    assert_eq!(registry.param_shape(pkcs11_types::CkMechanismType::AES_GCM.0), Some("gcm"));\n'
                    '}\n', encoding="utf-8")
                command = ["cargo", f"+{toolchain}", "test", "--manifest-path",
                           str(project / "Cargo.toml"), "--quiet"]
            else:
                (project / "Cargo.toml").write_text(
                    f'[package]\nname = "release-layout-consumer"\nversion = "0.0.0"\nedition = "2024"\n'
                    f'[dependencies]\npkcs11-abi = {{ path = {abi}, default-features = false }}\n'
                    f'pkcs11-module = {{ path = {module}, default-features = false }}\n'
                    f'[patch.crates-io]\npkcs11-abi = {{ path = {abi} }}\n', encoding="utf-8")
                (project / "src" / "lib.rs").write_text(
                    '#![no_std]\npub fn layout_bytes() -> usize {\n'
                    '    pkcs11_module::table_bytes(pkcs11_abi::LinuxLayout::Ilp32, 104).unwrap()\n'
                    '}\n', encoding="utf-8")
                command = ["cargo", f"+{toolchain}", "check", "--manifest-path",
                           str(project / "Cargo.toml"), "--quiet"]
            result = subprocess.run(command, text=True, capture_output=True)
            require(result.returncode == 0, f"{mode} consumer failed:\n{result.stdout}{result.stderr}")
            if mode == "layout-only":
                tree = subprocess.run(["cargo", f"+{toolchain}", "tree", "--manifest-path",
                                       str(project / "Cargo.toml"), "--edges", "normal",
                                       "--prefix", "none", "--format", "{p}"],
                                      text=True, capture_output=True)
                require(tree.returncode == 0, f"layout dependency tree failed: {tree.stderr}")
                names = {line.strip().split()[0] for line in tree.stdout.splitlines() if line.strip()}
                require(names == {"release-layout-consumer", "pkcs11-abi", "pkcs11-module"},
                        f"layout-only consumer has unexpected dependencies: {sorted(names)}")


def contains_dependencies(value: object) -> bool:
    if isinstance(value, dict):
        if any(key in value for key in ("dependencies", "dev-dependencies", "build-dependencies",
                                        "patch", "replace")):
            return True
        return any(contains_dependencies(child) for child in value.values())
    if isinstance(value, list):
        return any(contains_dependencies(child) for child in value)
    return False


def prepare_probe(repo: Path, destination: Path, run_id: str, attempt: str) -> str:
    require(bool(NUMBER.fullmatch(run_id) and NUMBER.fullmatch(attempt)),
            "run-id and attempt must be unsigned decimal integers without leading zeros")
    template = repo / "tools" / "publish-probe"
    manifest_path = template / "Cargo.toml"
    manifest = parse_toml(manifest_path)
    package = manifest.get("package", {})
    require(package.get("publish") == ["staging"], "probe must permit only staging publication")
    require(not contains_dependencies(manifest), "probe must not declare dependencies or patches")
    require(isinstance(package.get("name"), str) and package.get("name"), "probe name is missing")
    require(package.get("version") == "0.0.0", "probe template version must be 0.0.0")
    require(manifest.get("workspace") == {}, "probe must be a standalone workspace")
    for license_name in ("LICENSE-APACHE", "LICENSE-MIT"):
        require((repo / license_name).is_file(), f"missing root {license_name}")
    require(not destination.exists(), f"probe destination already exists: {destination}")
    for path in template.rglob("*"):
        require(not path.is_symlink(), f"probe template symlink forbidden: {path}")
    shutil.copytree(template, destination)
    for license_name in ("LICENSE-APACHE", "LICENSE-MIT"):
        shutil.copy2(repo / license_name, destination / license_name)
    new_version = f"0.0.0-ci.{run_id}.{attempt}"
    contents = (destination / "Cargo.toml").read_text(encoding="utf-8")
    package_section = re.search(r"(?ms)^\[package\]\s*\n(.*?)(?=^\[|\Z)", contents)
    require(package_section is not None, "probe manifest lacks [package] section")
    section = package_section.group(1)
    replaced, count = re.subn(r'(?m)^(\s*version\s*=\s*)"[^"]+"\s*$',
                              rf'\g<1>"{new_version}"', section)
    require(count == 1, "probe package version must appear exactly once")
    contents = contents[:package_section.start(1)] + replaced + contents[package_section.end(1):]
    (destination / "Cargo.toml").write_text(contents, encoding="utf-8")
    result = parse_toml(destination / "Cargo.toml")
    require(result.get("package", {}).get("version") == new_version
            and result["package"].get("publish") == ["staging"]
            and not contains_dependencies(result), "prepared probe has unsafe manifest")
    return new_version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    pre = commands.add_parser("preflight", help="check exact tag, versions, Git state")
    pre.add_argument("--ref", required=True)
    pre.add_argument("--require-main", action="store_true")
    archives = commands.add_parser("archives", help="inspect real Cargo .crate archives")
    archives.add_argument("--package-dir", type=Path, default=Path("target/package"))
    con = commands.add_parser("consumer", help="test unpacked archives as fresh Rust consumers")
    con.add_argument("--package-dir", type=Path, default=Path("target/package"))
    con.add_argument("--toolchain", default="1.88.0")
    probe = commands.add_parser("staging-probe", help="prepare a staging-only probe crate")
    probe.add_argument("--destination", required=True, type=Path)
    probe.add_argument("--run-id", required=True)
    probe.add_argument("--attempt", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "preflight":
            version = preflight(REPO_ROOT, args.ref, args.require_main)
            print(f"preflight: v{version} at HEAD, clean" + (", on origin/main" if args.require_main else ""))
        elif args.command == "archives":
            result = inspect_archives(REPO_ROOT, args.package_dir, write=True)
            print(f"archives: verified {len(result['packages'])} v{result['version']} packages; inventory and SHA256SUMS written")
        elif args.command == "consumer":
            consumer(REPO_ROOT, args.package_dir, args.toolchain)
            print(f"consumer: native and layout-only archives passed on Rust {args.toolchain}")
        elif args.command == "staging-probe":
            version = prepare_probe(REPO_ROOT, args.destination, args.run_id, args.attempt)
            print(f"staging-probe: prepared {version} at {args.destination}")
    except (ReleaseError, OSError) as exc:
        print(f"release check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
