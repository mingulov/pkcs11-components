//! PKCS#11 function-table layouts, catalogs, selection, and readers.
//!
//! Without the default `native` feature, this is a dependency-free `no_std`
//! crate for inspecting little-endian Linux LP64 and ILP32 table snapshots.
//! The `native` feature adds tables derived from the compilation target's
//! `cryptoki-sys` bindings, helpers for live native tables, and native
//! parameter declarations in the `params` module.
//!
//! Version and provenance values passed to selection APIs are assertions made
//! by the caller. This crate validates supported combinations and read bounds;
//! it does not authenticate where a table came from.

#![cfg_attr(not(feature = "native"), no_std)]

pub mod layout;
#[cfg(feature = "native")]
pub mod params;
#[cfg(kani)]
mod proofs;
#[cfg(feature = "native")]
pub mod tables;

pub use layout::{
    FUNCTION_NAMES, InterfaceLayout, LayoutError, LinuxLayout, Provenance, Selection, Version,
    function_name, function_offset, read_function_pointer, read_word_le, select, table_bytes,
};
#[cfg(feature = "native")]
pub use params::{
    CK_MU_GEN_PARAMS, CK_MU_GEN_PARAMS_PTR, CK_X9_42_MQV_DERIVE_PARAMS,
    CK_X9_42_MQV_DERIVE_PARAMS_PTR, CKM_ML_DSA_EXTERNAL_MU, CKM_ML_DSA_EXTERNAL_MU_GEN,
};
#[cfg(feature = "native")]
pub use tables::{
    FUNCTION_LIST_3_0_EXTRA_FIELDS, FUNCTION_LIST_3_2_EXTRA_FIELDS, FUNCTION_LIST_FIELDS, FnField,
    Surface, TableSet, TableSpan, detect_null_functions, read_fn_pointers, tables_for,
};
