//! Native parameter declarations for little-endian Linux LP64/ILP32.
//!
//! The MQV declaration uses the corrected PKCS#11 3.2 pointer field names.
//! The external-mu identifiers and parameters are proposed PKCS#11 3.3
//! additions.
//!
//! These structs borrow raw pointers. They neither own nor validate buffers,
//! handles, lengths, or provider support. Callers must keep each pointee live
//! for every provider access and satisfy the provider's synchronization and
//! parameter requirements. Copying a struct copies its pointers, not its data.
//! `Default` supplies zero scalars and null pointers for construction; it does
//! not produce parameters valid for a provider call.

#![allow(non_camel_case_types, non_snake_case)]

use cryptoki_sys::{
    CK_BYTE_PTR, CK_MECHANISM_TYPE, CK_OBJECT_HANDLE, CK_ULONG, CK_X9_42_DH_KDF_TYPE,
};

/// X9.42 MQV parameters using the published `pOtherInfo`, `pPublicData`, and
/// `pPublicData2` field names.
///
/// This is layout-compatible with `cryptoki-sys` 0.5's MQV declaration, whose
/// corresponding fields omit the `p` prefix. It is a distinct Rust type.
/// Pointer validity and ownership requirements are described in [`self`].
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct CK_X9_42_MQV_DERIVE_PARAMS {
    pub kdf: CK_X9_42_DH_KDF_TYPE,
    pub ulOtherInfoLen: CK_ULONG,
    pub pOtherInfo: CK_BYTE_PTR,
    pub ulPublicDataLen: CK_ULONG,
    pub pPublicData: CK_BYTE_PTR,
    pub ulPrivateDataLen: CK_ULONG,
    pub hPrivateData: CK_OBJECT_HANDLE,
    pub ulPublicDataLen2: CK_ULONG,
    pub pPublicData2: CK_BYTE_PTR,
    pub publicKey: CK_OBJECT_HANDLE,
}

/// Raw pointer to caller-managed [`CK_X9_42_MQV_DERIVE_PARAMS`].
pub type CK_X9_42_MQV_DERIVE_PARAMS_PTR = *mut CK_X9_42_MQV_DERIVE_PARAMS;

/// Proposed parameters for [`CKM_ML_DSA_EXTERNAL_MU_GEN`].
///
/// `hKey` selects a public/private key, or `pTR`/`ulTRLen` supply precomputed
/// TR; `pctx`/`ulctxLen` carry the context. The lowercase `ctx` field names
/// match the proposed native layout.
/// Callers and providers validate key/TR/context combinations and buffer
/// extents; the struct does not validate them.
#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct CK_MU_GEN_PARAMS {
    pub hKey: CK_OBJECT_HANDLE,
    pub pTR: CK_BYTE_PTR,
    pub ulTRLen: CK_ULONG,
    pub pctx: CK_BYTE_PTR,
    pub ulctxLen: CK_ULONG,
}

/// Raw pointer to caller-managed [`CK_MU_GEN_PARAMS`].
pub type CK_MU_GEN_PARAMS_PTR = *mut CK_MU_GEN_PARAMS;

/// Proposed ML-DSA external-mu generation identifier (`0x403b`).
///
/// Requires [`CK_MU_GEN_PARAMS`].
pub const CKM_ML_DSA_EXTERNAL_MU_GEN: CK_MECHANISM_TYPE = 0x403b;

/// Proposed ML-DSA signing/verification of externally generated mu (`0x403c`).
///
/// The proposal allows optional `CK_SIGN_ADDITIONAL_CONTEXT`:
/// its hedge variant is used and its context is ignored. Provider support
/// and input validity must be established by the caller.
pub const CKM_ML_DSA_EXTERNAL_MU: CK_MECHANISM_TYPE = 0x403c;
