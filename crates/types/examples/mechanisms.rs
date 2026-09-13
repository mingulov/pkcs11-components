use pkcs11_types::{CkMechanismType, MechanismRegistry};

fn main() -> Result<(), String> {
    let registry = MechanismRegistry::load(None)?;
    let shape = registry.param_shape(CkMechanismType::AES_GCM.0);
    println!("CKM_AES_GCM parameter shape: {shape:?}");
    // Expected: Some("gcm"). This describes the parameter representation in
    // the registry; it does not claim that a provider supports AES-GCM.
    Ok(())
}
