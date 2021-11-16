use std::iter;

use blstrs::{
    group::{ff::Field, Curve, Group},
    G1Affine, G1Projective, Scalar,
};
use rand_core::RngCore;
use tiny_keccak::{Hasher, Sha3};

use crate::pedersen_commitment::{PedersenCommitter, RevealedCommitment};

/// Hashes a point to another point on the G1 curve
fn hash_to_curve(p: G1Projective) -> G1Projective {
    const DOMAIN: &[u8; 35] = b"blst-ringct-signature-hash-to-curve";
    G1Projective::hash_to_curve(&p.to_compressed(), DOMAIN, &[])
}

pub struct TrueInput {
    pub secret_key: Scalar,
    pub revealed_commitment: RevealedCommitment,
}

impl TrueInput {
    pub fn public_key(&self) -> G1Projective {
        G1Projective::generator() * self.secret_key
    }

    /// Computes the Key Image for this inputs keypair
    /// A key image is defined to be I = x * Hp(P)
    pub fn key_image(&self) -> G1Projective {
        hash_to_curve(self.public_key()) * self.secret_key
    }
}

pub struct DecoyInput {
    pub public_key: G1Affine,
    pub commitment: G1Affine,
}

impl DecoyInput {
    fn public_key(&self) -> G1Affine {
        self.public_key
    }

    fn commitment(&self) -> G1Affine {
        self.commitment
    }
}

pub struct Output {
    pub public_key: G1Affine,
    pub amount: Scalar,
}

impl Output {
    fn public_key(&self) -> G1Affine {
        self.public_key
    }

    fn amount(&self) -> Scalar {
        self.amount
    }
}

pub struct RingCT {
    true_inputs: Vec<TrueInput>,
    decoy_inputs: Vec<Vec<DecoyInput>>,
    outputs: Vec<Output>,
}

#[derive(Debug)]
pub struct RingCTSignature {
    c0: Vec<Scalar>,
    r: Vec<Vec<(Scalar, Scalar)>>,
    key_images: Vec<G1Affine>,
}

impl RingCT {
    pub fn sign(
        &self,
        msg: &[u8],
        mut rng: impl RngCore,
    ) -> (RingCTSignature, Vec<Vec<(G1Affine, G1Affine)>>) {
        let ring_size = self.decoy_inputs.len() + 1; // +1 for true_inputs
        for decoy_inputs in self.decoy_inputs.iter() {
            assert_eq!(decoy_inputs.len(), self.true_inputs.len());
        }

        let pi = rng.next_u32() as usize % ring_size;

        let public_keys: Vec<Vec<G1Affine>> = {
            let mut keys = Vec::from_iter(
                self.decoy_inputs
                    .iter()
                    .map(|decoys| Vec::from_iter(decoys.iter().map(DecoyInput::public_key))),
            );

            keys.insert(
                pi,
                Vec::from_iter(
                    self.true_inputs
                        .iter()
                        .map(|input| input.public_key().to_affine()),
                ),
            );

            keys
        };

        let committer = PedersenCommitter::default();
        let commitments: Vec<Vec<G1Affine>> = {
            let mut commitments = Vec::from_iter(
                self.decoy_inputs
                    .iter()
                    .map(|decoys| Vec::from_iter(decoys.iter().map(DecoyInput::commitment))),
            );

            commitments.insert(
                pi,
                Vec::from_iter(
                    self.true_inputs
                        .iter()
                        .map(|input| committer.from_reveal(input.revealed_commitment).to_affine()),
                ),
            );

            commitments
        };

        let revealed_pseudo_commitments =
            Vec::from_iter(self.true_inputs.iter().map(|input| RevealedCommitment {
                value: input.revealed_commitment.value,
                blinding: Scalar::random(&mut rng),
            }));

        let revealed_output_commitments = {
            let mut commitments = Vec::from_iter(
                self.outputs
                    .iter()
                    .take(self.outputs.len() - 1)
                    .map(Output::amount)
                    .map(|value| RevealedCommitment {
                        value,
                        blinding: Scalar::random(&mut rng),
                    }),
            );

            let output_blinding_correction = revealed_pseudo_commitments
                .iter()
                .map(RevealedCommitment::blinding)
                .sum::<Scalar>()
                - commitments
                    .iter()
                    .map(RevealedCommitment::blinding)
                    .sum::<Scalar>();

            if let Some(last_output) = self.outputs.last() {
                commitments.push(RevealedCommitment {
                    value: last_output.amount,
                    blinding: output_blinding_correction,
                });
            } else {
                panic!("Expected at least one output")
            }

            commitments
        };

        let pseudo_commitments = Vec::from_iter(
            revealed_pseudo_commitments
                .iter()
                .map(|c| committer.from_reveal(*c)),
        );
        assert_eq!(
            pseudo_commitments.iter().sum::<G1Projective>(),
            revealed_output_commitments
                .iter()
                .map(|c| committer.from_reveal(*c))
                .sum()
        );

        let rings: Vec<Vec<(G1Affine, G1Affine)>> =
            Vec::from_iter((0..self.true_inputs.len()).into_iter().map(|m| {
                Vec::from_iter((0..ring_size).into_iter().map(|n| {
                    (
                        public_keys[n][m],
                        (commitments[n][m] - pseudo_commitments[m]).to_affine(),
                    )
                }))
            }));

        // At this point we've prepared our data for the ring signature, all that's left to do is perform the MLSAG signature

        let key_images = Vec::from_iter(self.true_inputs.iter().map(TrueInput::key_image));

        // MxN
        let mut c: Vec<Vec<Scalar>> = Vec::from_iter(
            iter::repeat(Vec::from_iter(iter::repeat(Scalar::zero()).take(ring_size)))
                .take(self.true_inputs.len()),
        );

        // MxNx2
        let mut r: Vec<Vec<(Scalar, Scalar)>> = Vec::from_iter(
            iter::repeat(Vec::from_iter(
                iter::repeat((Scalar::random(&mut rng), Scalar::random(&mut rng))).take(ring_size),
            ))
            .take(self.true_inputs.len()),
        );

        // We create a ring signature for each input
        #[allow(non_snake_case)]
        let G1 = G1Projective::generator();

        for (m, input) in self.true_inputs.iter().enumerate() {
            // for ring m, the true secret keys in this ring are ...
            let secret_keys = (
                input.secret_key,
                input.revealed_commitment.blinding - revealed_pseudo_commitments[m].blinding,
            );
            assert_eq!(
                committer.commit(0.into(), secret_keys.1),
                rings[m][pi].1.into()
            );
            println!("input  comm: {:?}", input.revealed_commitment);
            println!("pseudo comm: {:?}", revealed_pseudo_commitments[m]);

            let alpha = (Scalar::random(&mut rng), Scalar::random(&mut rng));
            c[m][(pi + 1) % ring_size] = c_hash(
                msg,
                G1 * alpha.0,
                G1 * alpha.1,
                hash_to_curve(rings[m][pi].0.into()) * alpha.0,
            );

            for offset in 1..ring_size {
                let n = (pi + offset) % ring_size;
                c[m][(n + 1) % ring_size] = c_hash(
                    msg,
                    G1 * r[m][n].0 + rings[m][n].0 * c[m][n],
                    G1 * r[m][n].1 + rings[m][n].1 * c[m][n],
                    hash_to_curve(rings[m][n].0.into()) * r[m][n].0 + key_images[m] * c[m][n],
                );
            }

            r[m][pi] = (
                alpha.0 - c[m][pi] * secret_keys.0,
                alpha.1 - c[m][pi] * secret_keys.1,
            );

            // For our sanity, check a few identities
            assert_eq!(G1 * secret_keys.0, rings[m][pi].0.into());
            assert_eq!(G1 * secret_keys.1, rings[m][pi].1.into());
            assert_eq!(
                G1 * (alpha.0 - c[m][pi] * secret_keys.0),
                G1 * alpha.0 - G1 * (c[m][pi] * secret_keys.0)
            );
            assert_eq!(
                G1 * (alpha.1 - c[m][pi] * secret_keys.1),
                G1 * alpha.1 - G1 * (c[m][pi] * secret_keys.1)
            );
            assert_eq!(
                G1 * (alpha.0 - c[m][pi] * secret_keys.0) + rings[m][pi].0 * c[m][pi],
                G1 * alpha.0
            );
            assert_eq!(
                G1 * (alpha.1 - c[m][pi] * secret_keys.1) + rings[m][pi].1 * c[m][pi],
                G1 * alpha.1
            );
            assert_eq!(
                G1 * r[m][pi].0 + rings[m][pi].0 * c[m][pi],
                G1 * (alpha.0 - c[m][pi] * secret_keys.0) + rings[m][pi].0 * c[m][pi]
            );
            assert_eq!(
                G1 * r[m][pi].1 + rings[m][pi].1 * c[m][pi],
                G1 * (alpha.1 - c[m][pi] * secret_keys.1) + rings[m][pi].1 * c[m][pi]
            );
            assert_eq!(
                hash_to_curve(rings[m][pi].0.into()) * r[m][pi].0 + key_images[m] * c[m][pi],
                hash_to_curve(rings[m][pi].0.into()) * (alpha.0 - c[m][pi] * secret_keys.0)
                    + key_images[m] * c[m][pi]
            );
            assert_eq!(
                hash_to_curve(rings[m][pi].1.into()) * r[m][pi].1 + key_images[m] * c[m][pi],
                hash_to_curve(rings[m][pi].1.into()) * (alpha.1 - c[m][pi] * secret_keys.1)
                    + key_images[m] * c[m][pi]
            );

            assert_eq!(
                hash_to_curve(rings[m][pi].0.into()) * secret_keys.0,
                key_images[m]
            );
            assert_eq!(
                hash_to_curve(rings[m][pi].0.into()) * r[m][pi].0 + key_images[m] * c[m][pi],
                hash_to_curve(rings[m][pi].0.into()) * (alpha.0 - c[m][pi] * secret_keys.0)
                    + key_images[m] * c[m][pi]
            );
            assert_eq!(
                hash_to_curve(rings[m][pi].1.into()) * r[m][pi].1 + key_images[m] * c[m][pi],
                hash_to_curve(rings[m][pi].1.into()) * (alpha.1 - c[m][pi] * secret_keys.1)
                    + key_images[m] * c[m][pi]
            );
        }

        let sig = RingCTSignature {
            c0: Vec::from_iter(c.iter().map(|c| c[0])),
            r,
            key_images: Vec::from_iter(key_images.iter().map(Curve::to_affine)),
        };

        println!("pi: {}", pi);
        println!("c: {:#?}", c);

        (sig, rings)
    }
}

pub fn verify(msg: &[u8], sig: RingCTSignature, rings: Vec<Vec<(G1Affine, G1Affine)>>) -> bool {
    #[allow(non_snake_case)]
    let G1 = G1Projective::generator();

    // Verify key images are in G
    for key_image in sig.key_images.iter() {
        if !bool::from(key_image.is_on_curve()) {
            println!("Key images not on curve");
            return false;
        }
    }

    for (m, ring) in rings.iter().enumerate() {
        let mut cprime = Vec::from_iter(iter::repeat(Scalar::zero()).take(ring.len()));
        cprime[0] = sig.c0[m];

        for (n, keys) in ring.iter().enumerate() {
            cprime[(n + 1) % ring.len()] = c_hash(
                msg,
                G1 * sig.r[m][n].0 + keys.0 * cprime[n],
                G1 * sig.r[m][n].1 + keys.1 * cprime[n],
                hash_to_curve(keys.0.into()) * sig.r[m][n].0 + sig.key_images[m] * cprime[n],
            );
        }

        println!("c': {:#?}", cprime);
        if sig.c0[m] != cprime[0] {
            println!("Failed c check on ring {:?}", m);
            return false;
        }
    }

    // TODO: verify pseudo commitments match the output commitments
    true
}

fn c_hash(msg: &[u8], l1: G1Projective, l2: G1Projective, r1: G1Projective) -> Scalar {
    hash_to_scalar(&[
        msg,
        &l1.to_compressed(),
        &l2.to_compressed(),
        &r1.to_compressed(),
    ])
}

/// Hashes given material to a Scalar, repeated hashing is used if a hash can not be interpreted as a Scalar
fn hash_to_scalar(material: &[&[u8]]) -> Scalar {
    let mut sha3 = Sha3::v256();
    for chunk in material {
        sha3.update(chunk);
    }
    let mut hash = [0u8; 32];
    sha3.finalize(&mut hash);
    loop {
        let s_opt = Scalar::from_bytes_le(&hash);
        if bool::from(s_opt.is_some()) {
            return s_opt.unwrap();
        }

        let mut sha3 = Sha3::v256();
        sha3.update(&hash);
        sha3.finalize(&mut hash);
    }
}

#[cfg(test)]
mod tests {
    use blstrs::group::{ff::Field, Curve};
    use rand_core::OsRng;

    use super::*;
    #[test]
    fn test_ringct_sign() {
        let mut rng = OsRng::default();

        let ring_ct = RingCT {
            true_inputs: vec![TrueInput {
                secret_key: Scalar::random(&mut rng),
                revealed_commitment: RevealedCommitment {
                    value: 3.into(),
                    blinding: 5.into(),
                },
            }],
            decoy_inputs: vec![vec![DecoyInput {
                public_key: G1Projective::random(&mut rng).to_affine(),
                commitment: G1Projective::random(&mut rng).to_affine(),
            }]],
            outputs: vec![Output {
                public_key: G1Projective::random(&mut rng).to_affine(),
                amount: 3.into(),
            }],
        };

        let msg = b"hello";

        let (sig, rings) = ring_ct.sign(msg, rng);

        // println!("{:#?}", sig);
        // println!("{:#?}", rings);

        assert!(verify(msg, sig, rings));
    }
}
