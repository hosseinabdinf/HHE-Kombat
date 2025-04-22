
use tfhe::{core_crypto::commons::parameters::*, gadget::prelude::*};


pub const TRANSISTOR_ODD_PARAMETERS: GadgetParameters = GadgetParameters {
    lwe_dimension: LweDimension(788),
    glwe_dimension: GlweDimension(2),
    polynomial_size: PolynomialSize(1024),
    lwe_modular_std_dev: StandardDev(5.1281494858890686e-06),
    glwe_modular_std_dev: StandardDev(9.188173694010523e-16),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(4),
    ks_level: DecompositionLevelCount(3),
    encryption_key_choice: EncryptionKeyChoice::Big,
};


pub const TRANSISTOR_ODD_PARAMETERS_128: GadgetParameters = GadgetParameters {
    lwe_dimension: LweDimension(774),
    glwe_dimension: GlweDimension(1),
    polynomial_size: PolynomialSize(2048),
    lwe_modular_std_dev: StandardDev(6.580481810222767e-06),
    glwe_modular_std_dev: StandardDev(9.188173694010523e-16),
    pbs_base_log: DecompositionBaseLog(23),
    pbs_level: DecompositionLevelCount(1),
    ks_base_log: DecompositionBaseLog(3),
    ks_level: DecompositionLevelCount(5),
    encryption_key_choice: EncryptionKeyChoice::Big,
};