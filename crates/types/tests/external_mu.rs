use pkcs11_types::{
    CkMechanism, CkMechanismParams, CkMechanismType, MechanismRegistry, MuGenParams,
    PKCS11_3_2_OFFICIAL_MECHANISMS, SignAdditionalContext,
};

// Proposed PKCS#11 3.3 allocations.
const EXTERNAL_MU_GEN: u64 = 0x403b;
const EXTERNAL_MU: u64 = 0x403c;

#[test]
fn external_mu_generation_is_modeled_with_required_parameter_metadata() {
    let registry = MechanismRegistry::load(None).unwrap();
    assert_eq!(registry.param_shape(EXTERNAL_MU_GEN), Some("mu_gen"));
    assert!(!registry.is_parameterless(EXTERNAL_MU_GEN));
    assert_eq!(registry.check_operation(EXTERNAL_MU_GEN, true), Ok(()));
    // The registry checks representability, not provider semantics. It does
    // not reject missing required parameters; callers/providers validate them.
    assert_eq!(registry.check_operation(EXTERNAL_MU_GEN, false), Ok(()));
}

#[test]
fn external_mu_signing_has_optional_additional_context_parameters() {
    let registry = MechanismRegistry::load(None).unwrap();
    assert_eq!(registry.param_shape(EXTERNAL_MU), Some("sign_additional_context"));
    assert!(registry.is_parameterless(EXTERNAL_MU));
    assert_eq!(registry.check_operation(EXTERNAL_MU, true), Ok(()));
    assert_eq!(registry.check_operation(EXTERNAL_MU, false), Ok(()));
}

#[test]
fn external_mu_is_discoverable_but_not_in_the_official_3_2_catalog() {
    let registry =
        MechanismRegistry::load_with_override_str(Some("discovery_mode = 'filtered'")).unwrap();
    assert_eq!(
        registry.filter_mechanisms(&[EXTERNAL_MU_GEN, 0x7fff_ffff, EXTERNAL_MU]),
        vec![EXTERNAL_MU_GEN, EXTERNAL_MU]
    );
    for mechanism in [EXTERNAL_MU_GEN, EXTERNAL_MU] {
        assert!(registry.registered_mechanisms().contains(&mechanism));
        assert!(!PKCS11_3_2_OFFICIAL_MECHANISMS.contains(&CkMechanismType(mechanism)));
    }
}

#[test]
fn existing_owned_parameter_variants_construct_external_mu_invocations() {
    let generation = CkMechanism {
        mechanism_type: CkMechanismType::ML_DSA_EXTERNAL_MU_GEN,
        params: Some(CkMechanismParams::MuGen(MuGenParams {
            key_handle: 7,
            tr: vec![],
            context: b"context".to_vec(),
        })),
    };
    assert_eq!(generation.mechanism_type.0, EXTERNAL_MU_GEN);
    assert!(matches!(generation.params, Some(CkMechanismParams::MuGen(_))));
    let signature = CkMechanism {
        mechanism_type: CkMechanismType::ML_DSA_EXTERNAL_MU,
        params: Some(CkMechanismParams::SignAdditionalContext(SignAdditionalContext {
            hedge_variant: 0,
            context: vec![],
            hash: 0,
        })),
    };
    assert_eq!(signature.mechanism_type.0, EXTERNAL_MU);
    assert!(matches!(signature.params, Some(CkMechanismParams::SignAdditionalContext(_))));
}
