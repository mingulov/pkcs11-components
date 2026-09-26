//! Kani proofs for `CK_ULONG` width translation.
//!
//! These harnesses are compiled only under `cargo kani` (`--cfg kani`).
//! They prove totality, exact error behavior, and value preservation over
//! all inputs within the stated bounds; the unit and law tests in
//! `width.rs` pin concrete matrices. Run with:
//!
//! ```sh
//! cargo kani -p pkcs11-types
//! ```

use crate::width::{
    ByteOrder, CANONICAL_UNAVAILABLE, WidthError, all_ones, canonicalize_ulong,
    decanonicalize_ulong, narrow_info_field, reencode_ulong, translate_ulong_len,
};

fn any_order() -> ByteOrder {
    if kani::any() { ByteOrder::Little } else { ByteOrder::Big }
}

fn any_width() -> usize {
    if kani::any() { 4 } else { 8 }
}

/// The sentinel is total over all widths and exact for the valid ones.
#[kani::proof]
fn sentinel_is_total_and_exact() {
    let width: usize = kani::any();
    let ones = all_ones(width);
    if width == 4 {
        kani::assert(ones == 0xFFFF_FFFF, "32-bit sentinel");
    } else if width == 8 {
        kani::assert(ones == u64::MAX, "64-bit sentinel");
    }
}

/// Canonicalization maps exactly the native sentinel and passes every other
/// source-width value through; decanonicalization inverts it over the full
/// `u64` wire range and rejects exactly the unrepresentable values with
/// `Overflow` (never any other error).
#[kani::proof]
fn canonical_forms_round_trip_exactly() {
    let width = any_width();
    let ones = all_ones(width);
    // Canonicalization takes a source-width value; larger inputs are outside
    // its contract (a full-range `u64::MAX` passes through as itself, which
    // coincides with the canonical sentinel).
    let native: u64 = kani::any();
    kani::assume(native <= ones);
    let wire = canonicalize_ulong(native, width);
    kani::assert(
        (wire == CANONICAL_UNAVAILABLE) == (native == ones),
        "only the native sentinel becomes canonical",
    );
    kani::assert(wire == native || wire == CANONICAL_UNAVAILABLE, "no third outcome");

    // Decanonicalization takes any canonical wire value.
    let value: u64 = kani::any();
    match decanonicalize_ulong(value, width) {
        Ok(result) => {
            if value == CANONICAL_UNAVAILABLE {
                kani::assert(result == ones, "canonical maps to the native sentinel");
            } else {
                kani::assert(result == value && value <= ones, "representable values pass through");
            }
        }
        Err(error) => {
            kani::assert(error == WidthError::Overflow, "only Overflow is reported");
            kani::assert(value != CANONICAL_UNAVAILABLE && value > ones, "Overflow is exact");
        }
    }
}

/// Info-field narrowing never exceeds the destination width and never
/// truncates: the result is the input value or the native sentinel.
#[kani::proof]
fn info_narrowing_never_truncates() {
    let value: u64 = kani::any();
    let width = any_width();
    let ones = all_ones(width);

    let narrowed = narrow_info_field(value, width);
    kani::assert(narrowed <= ones, "result fits the destination width");
    kani::assert(narrowed == value || narrowed == ones, "value or sentinel, never truncated");
}

/// Length translation is total over the full input range: widths outside
/// {4, 8} report `UnsupportedWidth`, unrepresentable rescalings report
/// `Overflow`, and every success follows the element-rescaling equation
/// exactly (checked in `u128` so the oracle itself cannot overflow). The
/// canonical sentinel maps to the destination-width sentinel.
#[kani::proof]
fn length_translation_rescales_exactly() {
    let len: u64 = kani::any();
    let src_width: usize = kani::any();
    let dst_width: usize = kani::any();

    let valid = (src_width == 4 || src_width == 8) && (dst_width == 4 || dst_width == 8);
    let result = translate_ulong_len(len, src_width, dst_width);
    kani::assert(
        (result == Err(WidthError::UnsupportedWidth)) == !valid,
        "bad widths report UnsupportedWidth",
    );
    if !valid {
        return;
    }
    if len == CANONICAL_UNAVAILABLE {
        kani::assert(result == Ok(all_ones(dst_width)), "sentinel maps to the native sentinel");
        return;
    }
    let rescaled = (len as u128 / src_width as u128) * dst_width as u128;
    if rescaled > u64::MAX as u128 {
        kani::assert(result == Err(WidthError::Overflow), "unrepresentable lengths overflow");
    } else {
        kani::assert(result == Ok(rescaled as u64), "rescaling equation");
    }
}

/// Decode one narrow element to its integer value, independent of the
/// width-conversion under test.
fn decode(element: &[u8], order: ByteOrder) -> u64 {
    let mut buf = [0u8; 8];
    match order {
        ByteOrder::Little => {
            buf[..element.len()].copy_from_slice(element);
            u64::from_le_bytes(buf)
        }
        ByteOrder::Big => {
            buf[8 - element.len()..].copy_from_slice(element);
            u64::from_be_bytes(buf)
        }
    }
}

/// Widening and same-width re-encoding never fail, preserve the element
/// count, and preserve every element's integer value. The 16-byte input
/// covers multi-element arrays (4x `u32` or 2x `u64`). The three widening
/// cases are enumerated with literal widths so loop bounds stay concrete;
/// byte order stays symbolic. Byte-identical round-trips compose from
/// per-direction value preservation and are additionally covered by the
/// randomized law tests in `width.rs`.
macro_rules! widening_proof {
    ($name:ident, $src:literal, $dst:literal) => {
        #[kani::proof]
        #[kani::unwind(6)]
        fn $name() {
            let bytes: [u8; 16] = kani::any();
            let order = any_order();
            let widened = match reencode_ulong(&bytes, $src, $dst, order) {
                Ok(widened) => widened,
                Err(_) => {
                    kani::assert(false, "widening never fails");
                    return;
                }
            };
            const COUNT: usize = 16 / $src;
            kani::assert(widened.len() == COUNT * $dst, "element count preserved");
            kani::assume(widened.len() == COUNT * $dst);
            for i in 0..COUNT {
                let input = decode(&bytes[i * $src..][..$src], order);
                let output = decode(&widened[i * $dst..][..$dst], order);
                kani::assert(input == output, "every element value preserved");
            }
        }
    };
}
widening_proof!(widening_4_to_8_preserves_values, 4, 8);
widening_proof!(widening_4_to_4_preserves_values, 4, 4);
widening_proof!(widening_8_to_8_preserves_values, 8, 8);

/// Narrowing succeeds if and only if every element fits the destination
/// width — one unrepresentable element poisons the array with `Overflow`
/// instead of truncating — and successful narrowings preserve every
/// element's integer value.
#[kani::proof]
#[kani::unwind(6)]
fn narrowing_reencode_rejects_exactly_the_unrepresentable() {
    let bytes: [u8; 16] = kani::any();
    let order = any_order();

    let mut exceeds = false;
    for chunk in bytes.chunks_exact(8) {
        exceeds |= decode(chunk, order) > all_ones(4);
    }

    match reencode_ulong(&bytes, 8, 4, order) {
        Ok(narrowed) => {
            kani::assert(!exceeds, "success implies all elements fit");
            kani::assert(narrowed.len() == 8, "element count preserved");
            kani::assume(narrowed.len() == 8);
            for i in 0..2 {
                let input = decode(&bytes[i * 8..][..8], order);
                let output = decode(&narrowed[i * 4..][..4], order);
                kani::assert(input == output, "every element value preserved");
            }
        }
        Err(error) => {
            kani::assert(error == WidthError::Overflow, "only Overflow is reported");
            kani::assert(exceeds, "Overflow implies an unrepresentable element");
        }
    }
}

/// Error precedence is exact over all lengths and all 8-bit widths:
/// widths outside {4, 8} report `UnsupportedWidth` first, then a
/// non-multiple length reports `Misaligned`. Widths are bounded to `u8`
/// (0..=255 covers every interesting class: 0, 1..=3, 4, 5..=7, 8, 9..);
/// the implementation accepts only widths equal to 4 or 8.
#[kani::proof]
#[kani::unwind(10)]
fn reencode_error_precedence_is_exact() {
    let bytes: [u8; 32] = kani::any();
    let order = any_order();
    let len: usize = kani::any();
    let src_width = kani::any::<u8>() as usize;
    let dst_width = kani::any::<u8>() as usize;
    kani::assume(len <= bytes.len());

    let valid = (src_width == 4 || src_width == 8) && (dst_width == 4 || dst_width == 8);
    let result = reencode_ulong(&bytes[..len], src_width, dst_width, order);
    kani::assert(
        (result == Err(WidthError::UnsupportedWidth)) == !valid,
        "bad widths report UnsupportedWidth",
    );
    if valid {
        kani::assert(
            (result == Err(WidthError::Misaligned)) == (len % src_width != 0),
            "short tails report Misaligned",
        );
    }
}
