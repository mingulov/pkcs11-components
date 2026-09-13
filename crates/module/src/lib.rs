//! Raw PKCS#11 provider acquisition and ABI-layout reexports.
//!
//! With the default `native` feature, `function_list` and `interface_list`
//! call provider exports without calling `C_Initialize`. Loading a provider can
//! execute foreign code, and pointers returned by acquisition remain usable
//! only while the provider library and its data remain valid.
//!
//! Without default features this is a dependency-free `no_std` facade over the
//! target-layout APIs from [`pkcs11_abi`]; native tables and acquisition are not
//! available.

#![cfg_attr(not(feature = "native"), no_std)]

#[cfg(feature = "native")]
pub mod acquire;

pub use pkcs11_abi::layout;
#[cfg(feature = "native")]
pub use pkcs11_abi::tables;

#[cfg(feature = "native")]
pub use acquire::{RawInterface, function_list, interface_list};
#[cfg(feature = "native")]
pub use pkcs11_abi::{
    FUNCTION_LIST_3_0_EXTRA_FIELDS, FUNCTION_LIST_3_2_EXTRA_FIELDS, FUNCTION_LIST_FIELDS, FnField,
    Surface, TableSet, TableSpan, detect_null_functions, read_fn_pointers, tables_for,
};
pub use pkcs11_abi::{
    FUNCTION_NAMES, InterfaceLayout, LayoutError, LinuxLayout, Provenance, Selection, Version,
    function_name, function_offset, read_function_pointer, read_word_le, select, table_bytes,
};
