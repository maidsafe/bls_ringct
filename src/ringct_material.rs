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

#[derive(Clone, Copy)]
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
    mlsags: Vec<MlsagSignature>,
}

#[derive(Debug)]
pub struct MlsagSignature {
    c0: Scalar,
    r: Vec<(Scalar, Scalar)>,
    key_image: G1Affine,
    ring: Vec<(G1Affine, G1Affine)>,
}

impl RingCT {
    pub fn sign(&self, msg: &[u8], mut rng: impl RngCore) -> RingCTSignature {
        let ring_size = self.decoy_inputs.len() + 1; // +1 for true_inputs
        for decoy_inputs in self.decoy_inputs.iter() {
            assert_eq!(decoy_inputs.len(), self.true_inputs.len());
        }

        let committer = PedersenCommitter::default();
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

        // At this point we've prepared our data for the ring signature, all that's left to do is perform the MLSAG signature

        // We create a ring signature for each input
        let mut mlsags = Vec::new();
        for (m, input) in self.true_inputs.iter().enumerate() {
            mlsags.push(ringct_mlsag_sign(
                msg,
                input,
                self.decoy_inputs.iter().map(|decoy| decoy[m]).collect(),
                revealed_pseudo_commitments[m],
                &mut rng,
            ));
        }

        RingCTSignature { mlsags }
    }
}

fn ringct_mlsag_sign(
    msg: &[u8],
    input: &TrueInput,
    decoy_inputs: Vec<DecoyInput>,
    revealed_pseudo_commitment: RevealedCommitment,
    mut rng: impl RngCore,
) -> MlsagSignature {
    let committer = PedersenCommitter::default();
    #[allow(non_snake_case)]
    let G1 = G1Projective::generator(); // TAI: should we use committer.G instead?

    // The position of the true input will be randomply placed amongst the decoys
    let pi = rng.next_u32() as usize % (decoy_inputs.len() + 1);

    let public_keys: Vec<G1Affine> = {
        let mut keys = Vec::from_iter(decoy_inputs.iter().map(DecoyInput::public_key));
        keys.insert(pi, input.public_key().to_affine());
        keys
    };

    let commitments: Vec<G1Affine> = {
        let mut commitments = Vec::from_iter(decoy_inputs.iter().map(DecoyInput::commitment));
        commitments.insert(
            pi,
            committer.from_reveal(input.revealed_commitment).to_affine(),
        );
        commitments
    };

    let pseudo_commitment = committer.from_reveal(revealed_pseudo_commitment);
    let ring: Vec<(G1Affine, G1Affine)> = public_keys
        .into_iter()
        .zip(commitments)
        .map(|(pk, commitment)| (pk, (commitment - pseudo_commitment).to_affine()))
        .collect();

    // for ring m, the true secret keys in this ring are ...
    let secret_keys = (
        input.secret_key,
        input.revealed_commitment.blinding - revealed_pseudo_commitment.blinding,
    );
    assert_eq!(committer.commit(0.into(), secret_keys.1), ring[pi].1.into());
    let key_image = input.key_image();
    let alpha = (Scalar::random(&mut rng), Scalar::random(&mut rng));
    let mut r: Vec<(Scalar, Scalar)> = (0..ring.len())
        .map(|_| (Scalar::random(&mut rng), Scalar::random(&mut rng)))
        .collect();
    let mut c: Vec<Scalar> = (0..ring.len()).map(|_| Scalar::zero()).collect();

    c[(pi + 1) % ring.len()] = c_hash(
        msg,
        G1 * alpha.0,
        G1 * alpha.1,
        hash_to_curve(ring[pi].0.into()) * alpha.0,
    );

    for offset in 1..ring.len() {
        let n = (pi + offset) % ring.len();
        c[(n + 1) % ring.len()] = c_hash(
            msg,
            G1 * r[n].0 + ring[n].0 * c[n],
            G1 * r[n].1 + ring[n].1 * c[n],
            hash_to_curve(ring[n].0.into()) * r[n].0 + key_image * c[n],
        );
    }

    r[pi] = (
        alpha.0 - c[pi] * secret_keys.0,
        alpha.1 - c[pi] * secret_keys.1,
    );

    // For our sanity, check a few identities
    assert_eq!(G1 * secret_keys.0, ring[pi].0.into());
    assert_eq!(G1 * secret_keys.1, ring[pi].1.into());
    assert_eq!(
        G1 * (alpha.0 - c[pi] * secret_keys.0),
        G1 * alpha.0 - G1 * (c[pi] * secret_keys.0)
    );
    assert_eq!(
        G1 * (alpha.1 - c[pi] * secret_keys.1),
        G1 * alpha.1 - G1 * (c[pi] * secret_keys.1)
    );
    assert_eq!(
        G1 * (alpha.0 - c[pi] * secret_keys.0) + ring[pi].0 * c[pi],
        G1 * alpha.0
    );
    assert_eq!(
        G1 * (alpha.1 - c[pi] * secret_keys.1) + ring[pi].1 * c[pi],
        G1 * alpha.1
    );
    assert_eq!(
        G1 * r[pi].0 + ring[pi].0 * c[pi],
        G1 * (alpha.0 - c[pi] * secret_keys.0) + ring[pi].0 * c[pi]
    );
    assert_eq!(
        G1 * r[pi].1 + ring[pi].1 * c[pi],
        G1 * (alpha.1 - c[pi] * secret_keys.1) + ring[pi].1 * c[pi]
    );
    assert_eq!(
        hash_to_curve(ring[pi].0.into()) * r[pi].0 + key_image * c[pi],
        hash_to_curve(ring[pi].0.into()) * (alpha.0 - c[pi] * secret_keys.0) + key_image * c[pi]
    );
    assert_eq!(
        hash_to_curve(ring[pi].1.into()) * r[pi].1 + key_image * c[pi],
        hash_to_curve(ring[pi].1.into()) * (alpha.1 - c[pi] * secret_keys.1) + key_image * c[pi]
    );

    assert_eq!(hash_to_curve(ring[pi].0.into()) * secret_keys.0, key_image);
    assert_eq!(
        hash_to_curve(ring[pi].0.into()) * r[pi].0 + key_image * c[pi],
        hash_to_curve(ring[pi].0.into()) * (alpha.0 - c[pi] * secret_keys.0) + key_image * c[pi]
    );
    assert_eq!(
        hash_to_curve(ring[pi].1.into()) * r[pi].1 + key_image * c[pi],
        hash_to_curve(ring[pi].1.into()) * (alpha.1 - c[pi] * secret_keys.1) + key_image * c[pi]
    );

    MlsagSignature {
        c0: c[0],
        r,
        key_image: key_image.to_affine(),
        ring,
    }
}

pub fn verify(msg: &[u8], sig: RingCTSignature) -> bool {
    #[allow(non_snake_case)]
    let G1 = G1Projective::generator();

    // Verify key images are in G
    for mlsag in sig.mlsags.iter() {
        if !bool::from(mlsag.key_image.is_on_curve()) {
            // TODO: I don't think this is enough, we need to check that key_image is in the group as well
            println!("Key images not on curve");
            return false;
        }
    }

    for (m, mlsag) in sig.mlsags.iter().enumerate() {
        let mut cprime = Vec::from_iter((0..mlsag.ring.len()).map(|_| Scalar::zero()));
        cprime[0] = mlsag.c0;

        for (n, keys) in mlsag.ring.iter().enumerate() {
            cprime[(n + 1) % mlsag.ring.len()] = c_hash(
                msg,
                G1 * mlsag.r[n].0 + keys.0 * cprime[n],
                G1 * mlsag.r[n].1 + keys.1 * cprime[n],
                hash_to_curve(keys.0.into()) * mlsag.r[n].0 + mlsag.key_image * cprime[n],
            );
        }

        println!("c': {:#?}", cprime);
        if mlsag.c0 != cprime[0] {
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

        let sig = ring_ct.sign(msg, rng);

        // println!("{:#?}", sig);
        // println!("{:#?}", rings);

        assert!(verify(msg, sig));
    }
}
