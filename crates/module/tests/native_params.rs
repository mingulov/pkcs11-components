#![cfg(feature = "native")]

#[test]
fn curated_native_parameters_are_shared_abi_reexports() {
    let mut mu = pkcs11_abi::CK_MU_GEN_PARAMS::default();
    let _: &pkcs11_module::CK_MU_GEN_PARAMS = &mu;
    let _: &pkcs11_module::params::CK_MU_GEN_PARAMS = &mu;
    let _: pkcs11_module::CK_MU_GEN_PARAMS_PTR = &mut mu;
    let mut mqv = pkcs11_abi::CK_X9_42_MQV_DERIVE_PARAMS::default();
    let _: &pkcs11_module::CK_X9_42_MQV_DERIVE_PARAMS = &mqv;
    let _: pkcs11_module::CK_X9_42_MQV_DERIVE_PARAMS_PTR = &mut mqv;
    assert_eq!(pkcs11_module::CKM_ML_DSA_EXTERNAL_MU_GEN, pkcs11_abi::CKM_ML_DSA_EXTERNAL_MU_GEN);
    assert_eq!(pkcs11_module::CKM_ML_DSA_EXTERNAL_MU, pkcs11_abi::CKM_ML_DSA_EXTERNAL_MU);
}
