//! Kani proofs for the target-layout facts.
//!
//! These harnesses are compiled only under `cargo kani` (`--cfg kani`).
//! They prove totality and exact error behavior over all inputs; the unit
//! tests in `layout.rs` pin concrete values. Run with:
//!
//! ```sh
//! cargo kani -p pkcs11-abi
//! ```

use crate::layout::{
    LayoutError, LinuxLayout, Provenance, Selection, Version, function_name, function_offset,
    read_function_pointer, read_word_le, table_bytes,
};

fn any_layout() -> LinuxLayout {
    if kani::any() { LinuxLayout::Lp64 } else { LinuxLayout::Ilp32 }
}

/// Offsets and prefix sizes are exact: in-catalog inputs always succeed and
/// never overflow; every out-of-catalog input is `FieldOutOfRange`.
#[kani::proof]
fn offsets_and_prefix_sizes_are_exact() {
    let layout = any_layout();
    let ordinal: usize = kani::any();
    let fields: usize = kani::any();

    if ordinal < 104 {
        let offset = function_offset(layout, ordinal).expect("in-catalog offset");
        let total = table_bytes(layout, 104).expect("full prefix");
        kani::assert(offset < total, "offset is inside the full prefix");
        kani::assert(function_name(ordinal).is_some(), "in-catalog name exists");
    } else {
        kani::assert(
            function_offset(layout, ordinal) == Err(LayoutError::FieldOutOfRange),
            "out-of-catalog offset is rejected",
        );
        kani::assert(function_name(ordinal).is_none(), "out-of-catalog name is absent");
    }

    kani::assert(
        table_bytes(layout, fields).is_ok() == (fields <= 104),
        "prefix size succeeds exactly for known prefixes",
    );
    if fields <= 103 {
        let prefix = table_bytes(layout, fields).expect("known prefix");
        let next = table_bytes(layout, fields + 1).expect("known prefix");
        kani::assert(prefix < next, "prefix sizes grow strictly");
    }
}

/// Word reads never panic and report the exact failure: `Ok` if and only if
/// a complete target word is present, `Truncated` for a short tail, and
/// `OffsetOverflow` only when the end address itself overflows.
#[kani::proof]
fn word_reads_report_exact_failures() {
    let bytes: [u8; 40] = kani::any();
    let layout = any_layout();
    let offset: usize = kani::any();
    let word = layout.word_bytes();

    match read_word_le(&bytes, layout, offset) {
        Ok(_) => {
            let end = offset.checked_add(word).expect("present word has no overflow");
            kani::assert(end <= bytes.len(), "Ok implies a complete word");
        }
        Err(LayoutError::Truncated) => {
            let end = offset.checked_add(word).expect("Truncated has no address overflow");
            kani::assert(end > bytes.len(), "Truncated implies a short tail");
        }
        Err(LayoutError::OffsetOverflow) => {
            kani::assert(offset.checked_add(word).is_none(), "overflow is reported exactly");
        }
        Err(LayoutError::FieldOutOfRange) => {
            kani::assert(false, "word reads never report FieldOutOfRange");
        }
    }
}

/// Ordinal reads respect the snapshot extent: with a snapshot of exactly
/// `fields` leading fields, reads succeed if and only if the ordinal is
/// below `fields` — no read of an unconfirmed tail, no missed known field.
#[kani::proof]
fn ordinal_reads_respect_the_snapshot_prefix() {
    let bytes: [u8; 848] = kani::any();
    let layout = any_layout();
    let fields: usize = kani::any();
    let ordinal: usize = kani::any();
    kani::assume(fields <= 104);

    let len = table_bytes(layout, fields).expect("known prefix");
    let snapshot = &bytes[..len];
    let result = read_function_pointer(snapshot, layout, ordinal);
    kani::assert(
        result.is_ok() == (ordinal < fields),
        "reads succeed exactly below the snapshot prefix",
    );
}

/// Selection is total and bounded: every version/provenance combination maps
/// to a decision whose field count never exceeds the 104-field catalog, and
/// the provenance policy holds (legacy 3.x degrades to a 68-field prefix,
/// unknown majors refuse).
#[kani::proof]
fn selection_is_total_and_bounded() {
    let provenance =
        if kani::any() { Provenance::LegacyFunctionList } else { Provenance::StandardInterface };
    let version = Version { major: kani::any(), minor: kani::any() };

    match crate::layout::select(provenance, version) {
        Selection::Exact(n) => {
            kani::assert(n <= 104, "exact selections fit the catalog");
        }
        Selection::KnownPrefix(n) => {
            kani::assert(n == 68 || n == 104, "known prefixes are 68 or 104 fields");
        }
        Selection::Refuse => {}
    }

    match provenance {
        Provenance::LegacyFunctionList => match version.major {
            3 => kani::assert(
                crate::layout::select(provenance, version) == Selection::KnownPrefix(68),
                "legacy 3.x degrades to the base prefix",
            ),
            2 => {
                let known_minor = matches!(version.minor, 0 | 1 | 10 | 11 | 20 | 30 | 40);
                match crate::layout::select(provenance, version) {
                    Selection::Exact(n) => kani::assert(
                        known_minor && (n == 67 || n == 68),
                        "legacy exacts are the known 2.x minors",
                    ),
                    Selection::KnownPrefix(n) => kani::assert(
                        !known_minor && n == 68,
                        "legacy unknown 2.x minors degrade to the base prefix",
                    ),
                    Selection::Refuse => kani::assert(false, "legacy 2.x never refuses"),
                }
            }
            _ => kani::assert(
                crate::layout::select(provenance, version) == Selection::Refuse,
                "legacy refuses unknown majors",
            ),
        },
        Provenance::StandardInterface => {
            if version.major == 3 && version.minor == 2 {
                kani::assert(
                    crate::layout::select(provenance, version) == Selection::Exact(104),
                    "standard 3.2 selects the full catalog",
                );
            }
            if version.major != 2 && version.major != 3 {
                kani::assert(
                    crate::layout::select(provenance, version) == Selection::Refuse,
                    "standard refuses unknown majors",
                );
            }
        }
    }
}
