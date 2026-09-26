//! Independent PKCS#11 contract regressions.
//!
//! Numeric expectations use `cryptoki-sys` independently of this crate's
//! catalogs. Parameter tests cover PKCS#11 3.2 and historical 2.40 contracts.

use pkcs11_types::{CkAttributeType, CkKeyType, CkRv, MechanismRegistry};

#[test]
fn unique_id_matches_the_standard_attribute_identifier() {
    assert_eq!(u128::from(CkAttributeType::UNIQUE_ID.0), u128::from(cryptoki_sys::CKA_UNIQUE_ID));
}

#[test]
fn key_types_match_independent_native_identifiers() {
    let cases = [
        ("SHA512_224", CkKeyType::SHA512_224, cryptoki_sys::CKK_SHA512_224_HMAC),
        ("SHA512_256", CkKeyType::SHA512_256, cryptoki_sys::CKK_SHA512_256_HMAC),
        ("SEED", CkKeyType::SEED, cryptoki_sys::CKK_SEED),
        ("GOSTR3410", CkKeyType::GOSTR3410, cryptoki_sys::CKK_GOSTR3410),
        ("GOSTR3411", CkKeyType::GOSTR3411, cryptoki_sys::CKK_GOSTR3411),
        ("GOST28147", CkKeyType::GOST28147, cryptoki_sys::CKK_GOST28147),
        ("CHACHA20", CkKeyType::CHACHA20, cryptoki_sys::CKK_CHACHA20),
        ("POLY1305", CkKeyType::POLY1305, cryptoki_sys::CKK_POLY1305),
        ("AES_XTS", CkKeyType::AES_XTS, cryptoki_sys::CKK_AES_XTS),
        ("SHA3_224", CkKeyType::SHA3_224, cryptoki_sys::CKK_SHA3_224_HMAC),
        ("SHA3_256", CkKeyType::SHA3_256, cryptoki_sys::CKK_SHA3_256_HMAC),
        ("SHA3_384", CkKeyType::SHA3_384, cryptoki_sys::CKK_SHA3_384_HMAC),
        ("SHA3_512", CkKeyType::SHA3_512, cryptoki_sys::CKK_SHA3_512_HMAC),
        ("BLAKE2B_160", CkKeyType::BLAKE2B_160, cryptoki_sys::CKK_BLAKE2B_160_HMAC),
        ("BLAKE2B_256", CkKeyType::BLAKE2B_256, cryptoki_sys::CKK_BLAKE2B_256_HMAC),
        ("BLAKE2B_384", CkKeyType::BLAKE2B_384, cryptoki_sys::CKK_BLAKE2B_384_HMAC),
        ("BLAKE2B_512", CkKeyType::BLAKE2B_512, cryptoki_sys::CKK_BLAKE2B_512_HMAC),
        ("SALSA20", CkKeyType::SALSA20, cryptoki_sys::CKK_SALSA20),
        ("X2RATCHET", CkKeyType::X2RATCHET, cryptoki_sys::CKK_X2RATCHET),
        ("EC_EDWARDS", CkKeyType::EC_EDWARDS, cryptoki_sys::CKK_EC_EDWARDS),
        ("EC_MONTGOMERY", CkKeyType::EC_MONTGOMERY, cryptoki_sys::CKK_EC_MONTGOMERY),
        ("HKDF", CkKeyType::HKDF, cryptoki_sys::CKK_HKDF),
    ];
    for (name, actual, expected) in cases {
        assert_eq!(u128::from(actual.0), u128::from(expected), "{name}");
    }
}

#[test]
fn local_is_classified_with_the_other_declared_boolean_attributes() {
    for attribute in [
        CkAttributeType::TOKEN,
        CkAttributeType::PRIVATE,
        CkAttributeType::SENSITIVE,
        CkAttributeType::ENCRYPT,
        CkAttributeType::DECRYPT,
        CkAttributeType::WRAP,
        CkAttributeType::UNWRAP,
        CkAttributeType::SIGN,
        CkAttributeType::VERIFY,
        CkAttributeType::EXTRACTABLE,
        CkAttributeType::LOCAL,
    ] {
        assert!(attribute.is_bool(), "{attribute:?}");
        assert!(!attribute.is_ulong(), "{attribute:?}");
    }
    assert!(!CkAttributeType::KEY_GEN_MECHANISM.is_bool());
    assert!(!CkAttributeType::VALUE.is_bool());
}

#[test]
fn gost_derivation_is_registered_under_the_derivation_identifier() {
    let registry = MechanismRegistry::load(None).unwrap();
    assert_eq!(registry.param_shape(0x1204), Some("gostr3410_derive"));
    assert_eq!(registry.check_operation(0x1204, true), Ok(()));
    assert_eq!(registry.param_shape(0x1201), None);
    assert_eq!(registry.check_operation(0x1201, true), Err(CkRv::MECHANISM_PARAM_INVALID));
}

#[test]
fn rc5_parameter_shapes_preserve_iv_and_mac_length_fields() {
    let registry = MechanismRegistry::load(None).unwrap();
    for (mechanism, shape) in [
        (0x0331, "rc5"),
        (0x0333, "rc5"),
        (0x0332, "rc5_cbc"),
        (0x0335, "rc5_cbc"),
        (0x0334, "rc5_mac_general"),
    ] {
        assert_eq!(registry.param_shape(mechanism), Some(shape), "{mechanism:#x}");
        assert!(!registry.is_parameterless(mechanism), "{mechanism:#x}");
        assert_eq!(registry.check_operation(mechanism, true), Ok(()));
    }
    assert!(registry.is_parameterless(0x0330));
}

#[test]
fn ssl3_mac_mechanisms_accept_the_required_output_length() {
    let registry = MechanismRegistry::load(None).unwrap();
    for mechanism in [0x0380, 0x0381] {
        assert_eq!(registry.param_shape(mechanism), Some("mac_general"));
        assert!(!registry.is_parameterless(mechanism));
        assert_eq!(registry.check_operation(mechanism, true), Ok(()));
    }
}

#[test]
fn unmodeled_premaster_version_parameters_are_not_advertised_as_parameterless() {
    let registry =
        MechanismRegistry::load_with_override_str(Some("discovery_mode = 'filtered'")).unwrap();
    for mechanism in [0x0370, 0x0374] {
        assert!(!registry.is_parameterless(mechanism));
        assert_eq!(registry.param_shape(mechanism), None);
        assert_eq!(registry.check_operation(mechanism, true), Err(CkRv::MECHANISM_PARAM_INVALID));
    }
    assert_eq!(registry.filter_mechanisms(&[0x0370, 0x1087, 0x0374]), vec![0x1087]);
}

#[test]
fn unmodeled_dsa_generation_parameters_are_not_advertised_as_parameterless() {
    let registry =
        MechanismRegistry::load_with_override_str(Some("discovery_mode = 'filtered'")).unwrap();
    for mechanism in [0x2003, 0x2004, 0x2005] {
        assert!(!registry.is_parameterless(mechanism), "{mechanism:#x}");
        assert_eq!(registry.param_shape(mechanism), None);
        assert_eq!(registry.check_operation(mechanism, true), Err(CkRv::MECHANISM_PARAM_INVALID));
    }
    // The older DSA domain generation mechanism has no parameter and remains supported.
    assert!(registry.is_parameterless(0x2000));
    assert_eq!(registry.filter_mechanisms(&[0x2003, 0x2000, 0x2004, 0x2005]), vec![0x2000]);
}
