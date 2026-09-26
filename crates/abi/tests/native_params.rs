#![cfg(feature = "native")]

use pkcs11_abi::{
    CK_MU_GEN_PARAMS, CK_MU_GEN_PARAMS_PTR, CK_X9_42_MQV_DERIVE_PARAMS,
    CK_X9_42_MQV_DERIVE_PARAMS_PTR, CKM_ML_DSA_EXTERNAL_MU, CKM_ML_DSA_EXTERNAL_MU_GEN,
};
use std::mem::{align_of, offset_of, size_of};

#[test]
fn parameter_structs_expose_c_field_names_and_null_defaults() {
    let mut mqv = CK_X9_42_MQV_DERIVE_PARAMS {
        kdf: 1,
        ulOtherInfoLen: 0,
        pOtherInfo: std::ptr::null_mut(),
        ulPublicDataLen: 0,
        pPublicData: std::ptr::null_mut(),
        ulPrivateDataLen: 0,
        hPrivateData: 7,
        ulPublicDataLen2: 0,
        pPublicData2: std::ptr::null_mut(),
        publicKey: 8,
    };
    let _: CK_X9_42_MQV_DERIVE_PARAMS_PTR = &mut mqv;
    let zero = CK_X9_42_MQV_DERIVE_PARAMS::default();
    assert!(zero.pOtherInfo.is_null() && zero.pPublicData.is_null() && zero.pPublicData2.is_null());
    assert_eq!(zero.kdf, 0);
    assert_eq!(zero.ulOtherInfoLen, 0);
    assert_eq!(zero.ulPublicDataLen, 0);
    assert_eq!(zero.ulPrivateDataLen, 0);
    assert_eq!(zero.hPrivateData, 0);
    assert_eq!(zero.ulPublicDataLen2, 0);
    assert_eq!(zero.publicKey, 0);

    let mut mu = CK_MU_GEN_PARAMS {
        hKey: 7,
        pTR: std::ptr::null_mut(),
        ulTRLen: 0,
        pctx: std::ptr::null_mut(),
        ulctxLen: 0,
    };
    let _: CK_MU_GEN_PARAMS_PTR = &mut mu;
    let zero = CK_MU_GEN_PARAMS::default();
    assert_eq!(zero.hKey, 0);
    assert!(zero.pTR.is_null() && zero.pctx.is_null());
    assert_eq!(zero.ulTRLen, 0);
    assert_eq!(zero.ulctxLen, 0);
    assert_eq!(CKM_ML_DSA_EXTERNAL_MU_GEN, 0x403b);
    assert_eq!(CKM_ML_DSA_EXTERNAL_MU, 0x403c);
    let _: pkcs11_abi::params::CK_MU_GEN_PARAMS = mu;
}

#[cfg(all(target_os = "linux", target_endian = "little"))]
#[test]
fn linux_native_parameter_offsets_match_lp64_and_ilp32() {
    let word = size_of::<usize>();
    assert!(word == 4 || word == 8);
    assert_eq!(size_of::<CK_X9_42_MQV_DERIVE_PARAMS>(), if word == 8 { 80 } else { 40 });
    assert_eq!(align_of::<CK_X9_42_MQV_DERIVE_PARAMS>(), word);
    assert_eq!(
        [
            offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, kdf),
            offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, ulOtherInfoLen),
            offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, pOtherInfo),
            offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, ulPublicDataLen),
            offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, pPublicData),
            offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, ulPrivateDataLen),
            offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, hPrivateData),
            offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, ulPublicDataLen2),
            offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, pPublicData2),
            offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, publicKey),
        ],
        [0, word, 2 * word, 3 * word, 4 * word, 5 * word, 6 * word, 7 * word, 8 * word, 9 * word]
    );
    assert_eq!(size_of::<CK_MU_GEN_PARAMS>(), if word == 8 { 40 } else { 20 });
    assert_eq!(align_of::<CK_MU_GEN_PARAMS>(), word);
    assert_eq!(
        [
            offset_of!(CK_MU_GEN_PARAMS, hKey),
            offset_of!(CK_MU_GEN_PARAMS, pTR),
            offset_of!(CK_MU_GEN_PARAMS, ulTRLen),
            offset_of!(CK_MU_GEN_PARAMS, pctx),
            offset_of!(CK_MU_GEN_PARAMS, ulctxLen),
        ],
        [0, word, 2 * word, 3 * word, 4 * word]
    );
}

#[test]
fn corrected_mqv_pointer_names_preserve_upstream_abi_offsets() {
    type Upstream = cryptoki_sys::CK_X9_42_MQV_DERIVE_PARAMS;
    assert_eq!(size_of::<CK_X9_42_MQV_DERIVE_PARAMS>(), size_of::<Upstream>());
    assert_eq!(align_of::<CK_X9_42_MQV_DERIVE_PARAMS>(), align_of::<Upstream>());
    assert_eq!(offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, pOtherInfo), offset_of!(Upstream, OtherInfo));
    assert_eq!(
        offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, pPublicData),
        offset_of!(Upstream, PublicData)
    );
    assert_eq!(
        offset_of!(CK_X9_42_MQV_DERIVE_PARAMS, pPublicData2),
        offset_of!(Upstream, PublicData2)
    );
}
