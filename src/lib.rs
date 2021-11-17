pub mod mlsag;
pub mod pedersen_commitment;
pub mod ringct;

use blstrs::G1Projective;

pub use blstrs;
pub use mlsag::{DecoyInput, MlsagMaterial, MlsagSignature, TrueInput};
pub use pedersen_commitment::{PedersenCommitter, RevealedCommitment};
pub use ringct::{Output, RingCtMaterial};

/// Hashes a point to another point on the G1 curve
pub fn hash_to_curve(p: G1Projective) -> G1Projective {
    const DOMAIN: &[u8; 25] = b"blst-ringct-hash-to-curve";
    G1Projective::hash_to_curve(&p.to_compressed(), DOMAIN, &[])
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
