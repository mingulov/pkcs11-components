//! CK_UNAVAILABLE_INFORMATION is (~0UL) at the native CK_ULONG width.
//! Run on both Linux LP64 and ILP32 in CI.
use cryptoki_sys::{CK_ULONG, CK_UNAVAILABLE_INFORMATION};
use pkcs11_types::width::{
    ByteOrder, CANONICAL_UNAVAILABLE, canonicalize_ulong, decanonicalize_ulong, narrow_info_field,
    reencode_ulong, translate_ulong_len,
};

#[test]
fn native_unsigned_minus_one_round_trips_through_canonical_form() {
    let native: CK_ULONG = !0;
    let width = std::mem::size_of::<CK_ULONG>();
    assert_eq!(native, CK_UNAVAILABLE_INFORMATION);
    let canonical = canonicalize_ulong(native as u64, width);
    assert_eq!(canonical, 0xffff_ffff_ffff_ffff);
    assert_eq!(decanonicalize_ulong(canonical, width), Ok(native as u64));
}

#[test]
fn unavailable_lengths_and_info_fields_preserve_all_ones_in_both_widths() {
    for (source_width, native) in [(4, 0xffff_ffff), (8, 0xffff_ffff_ffff_ffff)] {
        let canonical = canonicalize_ulong(native, source_width);
        assert_eq!(canonical, CANONICAL_UNAVAILABLE);
        for (destination_width, expected) in [(4, 0xffff_ffff), (8, 0xffff_ffff_ffff_ffff)] {
            assert_eq!(decanonicalize_ulong(canonical, destination_width), Ok(expected));
            assert_eq!(narrow_info_field(canonical, destination_width), expected);
            assert_eq!(
                translate_ulong_len(canonical, source_width, destination_width),
                Ok(expected)
            );
        }
    }
}

#[test]
fn ordinary_ulong_payload_widening_preserves_the_integer_value() {
    // In a numeric attribute payload, 0xffffffff is a value. The caller uses
    // sentinel-aware conversion specifically for lengths/counts that permit it.
    let widened = reencode_ulong(&[0xff; 4], 4, 8, ByteOrder::Little).unwrap();
    assert_eq!(widened, [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]);
    assert_eq!(canonicalize_ulong(0xffff_ffff, 8), 0xffff_ffff);
    assert_eq!(canonicalize_ulong(0, 4), 0);
    assert_eq!(narrow_info_field(0, 4), 0);
}
