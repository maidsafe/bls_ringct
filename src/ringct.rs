use blstrs::{G1Affine, G1Projective, Scalar};
use rand_core::RngCore;

use crate::{MlsagMaterial, MlsagSignature, PedersenCommitter, RevealedCommitment};

pub struct Output {
    pub public_key: G1Affine,
    pub amount: Scalar,
}

impl Output {
    pub fn public_key(&self) -> G1Affine {
        self.public_key
    }

    pub fn amount(&self) -> Scalar {
        self.amount
    }

    /// Generate a commitment to the input amount
    pub fn random_commitment(&self, rng: impl RngCore) -> RevealedCommitment {
        RevealedCommitment::from_value(self.amount, rng)
    }
}

pub struct RingCtMaterial {
    inputs: Vec<MlsagMaterial>,
    outputs: Vec<Output>,
}

impl RingCtMaterial {
    pub fn sign(&self, msg: &[u8], mut rng: impl RngCore) -> RingCtSignature {
        // We create a ring signature for each input
        let mut mlsags = Vec::new();
        let mut revealed_pseudo_commitments = Vec::new();
        for mlsag_material in self.inputs.iter() {
            let (mlsag, revealed_pseudo_commitment) = mlsag_material.sign(msg, &mut rng);
            mlsags.push(mlsag);
            revealed_pseudo_commitments.push(revealed_pseudo_commitment)
        }

        // Now prepare the output commitments
        let pedersen = PedersenCommitter::default();
        let revealed_output_commitments = {
            let mut output_commitments: Vec<RevealedCommitment> = self
                .outputs
                .iter()
                .map(|out| out.random_commitment(&mut rng))
                .take(self.outputs.len() - 1)
                .collect();

            let input_sum: Scalar = revealed_pseudo_commitments
                .iter()
                .map(RevealedCommitment::blinding)
                .sum();
            let output_sum: Scalar = output_commitments
                .iter()
                .map(RevealedCommitment::blinding)
                .sum();

            let output_blinding_correction = input_sum - output_sum;

            if let Some(last_output) = self.outputs.last() {
                output_commitments.push(RevealedCommitment {
                    value: last_output.amount,
                    blinding: output_blinding_correction,
                });
            } else {
                panic!("Expected at least one output")
            }

            output_commitments
        };

        let pseudo_commitments = Vec::from_iter(
            revealed_pseudo_commitments
                .iter()
                .map(|c| pedersen.from_reveal(*c)),
        );
        let output_commitments = Vec::from_iter(
            revealed_output_commitments
                .iter()
                .map(|c| pedersen.from_reveal(*c)),
        );

        assert_eq!(
            pseudo_commitments.iter().sum::<G1Projective>(),
            output_commitments.iter().sum()
        );

        // TODO: add commitments to the ring signature
        RingCtSignature { mlsags }
    }
}

#[derive(Debug)]
pub struct RingCtSignature {
    mlsags: Vec<MlsagSignature>,
}

impl RingCtSignature {
    pub fn verify(&self, msg: &[u8]) -> bool {
        for mlsag in self.mlsags.iter() {
            if !mlsag.verify(msg) {
                return false;
            }
        }

        // TODO: verify pseudo commitments match the output commitments
        true
    }
}

#[cfg(test)]
mod tests {
    use blstrs::group::{ff::Field, Curve, Group};
    use rand_core::OsRng;

    use crate::{DecoyInput, MlsagMaterial, TrueInput};

    use super::*;
    #[test]
    fn test_ringct_sign() {
        let mut rng = OsRng::default();

        let ring_ct = RingCtMaterial {
            inputs: vec![MlsagMaterial {
                true_input: TrueInput {
                    secret_key: Scalar::random(&mut rng),
                    revealed_commitment: RevealedCommitment {
                        value: 3.into(),
                        blinding: 5.into(),
                    },
                },
                decoy_inputs: vec![DecoyInput {
                    public_key: G1Projective::random(&mut rng).to_affine(),
                    commitment: G1Projective::random(&mut rng).to_affine(),
                }],
            }],
            outputs: vec![Output {
                public_key: G1Projective::random(&mut rng).to_affine(),
                amount: 3.into(),
            }],
        };

        let msg = b"hello";

        let sig = ring_ct.sign(msg, rng);

        // println!("{:#?}", sig);
        // println!("{:#?}", rings);

        assert!(sig.verify(msg));
    }
}
