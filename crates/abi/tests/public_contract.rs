use pkcs11_abi::{LinuxLayout, Selection, Version, function_name, select, table_bytes};

#[test]
fn target_layout_contract_is_public() {
    assert_eq!(function_name(0), Some("C_Initialize"));
    assert_eq!(function_name(103), Some("C_UnwrapKeyAuthenticated"));
    assert_eq!(table_bytes(LinuxLayout::Lp64, 104), Ok(840));
    assert_eq!(table_bytes(LinuxLayout::Ilp32, 104), Ok(420));
    assert_eq!(
        select(pkcs11_abi::Provenance::StandardInterface, Version { major: 3, minor: 2 },),
        Selection::Exact(104),
    );
}

#[cfg(feature = "native")]
#[test]
fn native_catalog_contract_is_public() {
    assert_eq!(pkcs11_abi::FUNCTION_LIST_FIELDS.len(), 68);
    assert_eq!(pkcs11_abi::FUNCTION_LIST_3_0_EXTRA_FIELDS.len(), 24);
    assert_eq!(pkcs11_abi::FUNCTION_LIST_3_2_EXTRA_FIELDS.len(), 12);
}
