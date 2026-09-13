use pkcs11_types::{
    CkMechanismType, CkRv, DiscoveryMode, MechanismRegistry, PKCS11_3_2_OFFICIAL_MECHANISMS,
};

#[test]
fn public_type_surface_is_available() {
    assert_eq!(CkRv::OK.0, 0);
    assert_eq!(CkMechanismType::RSA_PKCS_PSS.0, 0x0000_000d);
    assert_eq!(CkMechanismType::AES_GCM.0, 0x0000_1087);
    assert_eq!(DiscoveryMode::default(), DiscoveryMode::Transparent);
    assert!(!PKCS11_3_2_OFFICIAL_MECHANISMS.is_empty());

    let registry = MechanismRegistry::load(None).expect("embedded registry must parse");
    assert_eq!(registry.param_shape(CkMechanismType::AES_GCM.0), Some("gcm"));
}
