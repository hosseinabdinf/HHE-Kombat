use std::{env, fs, path::Path};

use crate::{
    filter::{Filter, FilterType},
    Torus,
};
use concrete_commons::{
    dispersion::StandardDev,
    key_kinds::BinaryKeyKind,
    parameters::{DecompositionBaseLog, DecompositionLevelCount, GlweDimension, PolynomialSize},
};
use concrete_core::crypto::secret::{generators::SecretRandomGenerator, GlweSecretKey};
use strum_macros::EnumIter;

pub struct Parameters {
    pub(crate) n: usize,
    pub(crate) key_size: usize,
    pub(crate) filter: Filter,
}

#[allow(non_camel_case_types)]
#[derive(Debug, EnumIter)]
pub enum SystemParameters {
    n1216,
    n1280,
    n144,
}

impl SystemParameters {
    pub fn parameters(&self) -> Parameters {
        match self {
            Self::n1216 => Parameters {
                key_size: 16384,
                n: 1216,
                filter: Filter::new(FilterType::DSM, &[128, 64, 0, 80, 0, 0, 0, 80]),
            },
            Self::n1280 => Parameters {
                key_size: 4096,
                n: 1280,
                filter: Filter::new(
                    FilterType::DSM,
                    &[128, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64],
                ),
            },
            Self::n144 => Parameters {
                key_size: 16384,
                n: 144,
                filter: Filter::new(FilterType::XorThr, &[81, 32]),
            },
        }
    }

    pub fn name(&self) -> String {
        (match self {
            SystemParameters::n1216 => "FiLIP 1216",
            SystemParameters::n1280 => "FiLIP 1280",
            SystemParameters::n144 => "FiLIP 144",
        })
        .to_string()
    }

    pub fn fhe_parameters(
        &self,
    ) -> (
        GlweDimension,
        PolynomialSize,
        DecompositionBaseLog,
        DecompositionLevelCount,
        StandardDev,
    ) {
        match self {
            SystemParameters::n1216 => (
                GlweDimension(1),
                PolynomialSize(1024),
                DecompositionBaseLog(5),
                DecompositionLevelCount(6),
                StandardDev::from_standard_dev(10_f64.powf(-9.0)),
            ),
            SystemParameters::n1280 => (
                GlweDimension(1),
                PolynomialSize(1024),
                DecompositionBaseLog(5),
                DecompositionLevelCount(6),
                StandardDev::from_standard_dev(10_f64.powf(-9.0)),
            ),
            SystemParameters::n144 => (
                GlweDimension(1),
                PolynomialSize(1024),
                DecompositionBaseLog(5),
                DecompositionLevelCount(6),
                StandardDev::from_standard_dev(10_f64.powf(-9.0)),
            ),
        }
    }

    pub fn generate_fhe_key(&self) -> GlweSecretKey<BinaryKeyKind, Vec<Torus>> {
        let env_var = env::var("KEY_DIRECTORY").ok();
        let path = env_var.as_ref().map(|s| &**s);
        let key_stored = path
            .map(|p| Path::new(format!("{}/keys/{}/fhe", p, self.name()).as_str()).is_dir())
            .unwrap_or(false);

        if key_stored {
            let sk_serialized = fs::read(format!(
                "{}/keys/{}/fhe/secret_key",
                path.unwrap(),
                self.name()
            ))
            .unwrap();
            bincode::deserialize(&sk_serialized).unwrap()
        } else {
            let mut secret_generator = SecretRandomGenerator::new(None);
            let (glwe_dimension, poly_size, _base_log, _level, _std_dev) = self.fhe_parameters();

            let sk =
                GlweSecretKey::generate_binary(glwe_dimension, poly_size, &mut secret_generator);
            if path.is_some() {
                fs::create_dir_all(format!("{}/keys/{}/fhe", path.unwrap(), self.name())).unwrap();
                fs::write(
                    format!("{}/keys/{}/fhe/secret_key", path.unwrap(), self.name()),
                    &bincode::serialize(&sk).unwrap(),
                )
                .unwrap();
            }
            sk
        }
    }
}
