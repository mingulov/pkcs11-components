fn through_module(value: pkcs11_abi::LinuxLayout) -> pkcs11_module::LinuxLayout {
    value
}

#[test]
fn layout_module_and_type_are_shared_reexports() {
    let value = through_module(pkcs11_abi::LinuxLayout::Ilp32);
    assert_eq!(value, pkcs11_module::layout::LinuxLayout::Ilp32);
}

#[cfg(feature = "native")]
#[test]
fn native_tables_are_shared_reexports() {
    fn accepts_module_fields(_: &'static [pkcs11_module::FnField]) {}
    accepts_module_fields(pkcs11_abi::FUNCTION_LIST_FIELDS);
    assert_eq!(
        pkcs11_module::FUNCTION_LIST_FIELDS.as_ptr(),
        pkcs11_abi::FUNCTION_LIST_FIELDS.as_ptr(),
    );
}

#[cfg(feature = "native")]
#[test]
fn acquisition_function_signature_is_preserved() {
    let _: fn(&libloading::Library) -> Result<*mut cryptoki_sys::CK_FUNCTION_LIST, String> =
        pkcs11_module::function_list;
}
