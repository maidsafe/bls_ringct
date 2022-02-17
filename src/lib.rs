pub mod error;
pub mod mlsag;
pub mod ringct;

use blstrs::{
    group::{ff::Field, Curve},
    G1Affine, G1Projective, Scalar,
};

pub use blstrs;
pub use error::Error;
pub use mlsag::{DecoyInput, MlsagMaterial, MlsagSignature, TrueInput};
pub use ringct::{Output, RingCtMaterial};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Error>;

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy)]
pub struct RevealedCommitment {
    pub value: u64,
    pub blinding: Scalar,
}

impl RevealedCommitment {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v: Vec<u8> = Default::default();
        v.extend(&self.value.to_le_bytes());
        v.extend(&self.blinding.to_bytes_le());
        v
    }

    /// Construct a revealed commitment from a value, generating a blinding randomly
    pub fn from_value(value: u64, mut rng: impl rand_core::RngCore) -> Self {
        Self {
            value,
            blinding: Scalar::random(&mut rng),
        }
    }

    pub fn commit(&self, pc_gens: &bulletproofs::PedersenGens) -> G1Projective {
        pc_gens.commit(Scalar::from(self.value), self.blinding)
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn blinding(&self) -> Scalar {
        self.blinding
    }
}

/// Hashes a point to another point on the G1 curve
pub fn hash_to_curve(p: G1Projective) -> G1Projective {
    const DOMAIN: &[u8; 25] = b"blst-ringct-hash-to-curve";
    G1Projective::hash_to_curve(&p.to_compressed(), DOMAIN, &[])
}

/// returns KeyImage for the given public key
pub fn key_image(public_key: G1Projective, secret_key: Scalar) -> G1Affine {
    (hash_to_curve(public_key) * secret_key).to_affine()
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
