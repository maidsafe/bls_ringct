use blstrs::{group::Group, G1Projective, Scalar};

const DOMAIN: &[u8; 27] = b"blst-ringct-pedersen-commit";

/// PedersenCommitter provides the ability to create Pedersen Commitments
/// of the form:
///     commit(v, r) = rG + vH
/// Where v is the value we are commiting to and r is the blinding factor.
///
/// Commitments will be on the G1 curve.
///     G is taken to be the G1 base point
///     H = hash_to_point(G)
/// It's important that no one may find γ s.t. H = γG, this is why we use `hash_to_point()`.
#[allow(non_snake_case)]
pub struct PedersenCommitter {
    G: G1Projective,
    H: G1Projective,
}

impl Default for PedersenCommitter {
    fn default() -> Self {
        #[allow(non_snake_case)]
        let G = G1Projective::generator();
        #[allow(non_snake_case)]
        let H = G1Projective::hash_to_curve(&G.to_compressed(), DOMAIN, &[]);
        Self { G, H }
    }
}

impl PedersenCommitter {
    /// Generates a Pedersen Commitment to `value` blinded by `blinding`.
    pub fn commit(&self, value: Scalar, blinding: Scalar) -> G1Projective {
        self.G * blinding + self.H * value
    }

    /// Generate a Pedersen Commitment form revealed commitment
    pub fn from_reveal(&self, reveal: RevealedCommitment) -> G1Projective {
        self.commit(reveal.value, reveal.blinding)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RevealedCommitment {
    pub value: Scalar,
    pub blinding: Scalar,
}

impl RevealedCommitment {
    pub fn value(&self) -> Scalar {
        self.value
    }

    pub fn blinding(&self) -> Scalar {
        self.blinding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck_macros::quickcheck;

    #[test]
    fn test_homomorphic_sum() {
        let committer = PedersenCommitter::default();

        let a = committer.commit(2.into(), 3.into());
        let b = committer.commit(5.into(), 1.into());
        let c = committer.commit(7.into(), 4.into());

        assert_eq!(a + b, c);
    }

    #[quickcheck]
    fn prop_homomorphic_sum(values_and_blindings: Vec<(u64, u64)>) {
        let committer = PedersenCommitter::default();
        let values_and_blindings = Vec::from_iter(
            values_and_blindings
                .into_iter()
                .map(|(a, b)| (Scalar::from(a), Scalar::from(b))),
        );

        let sum_a: Scalar = values_and_blindings.iter().map(|(a, _)| *a).sum();
        let sum_b: Scalar = values_and_blindings.iter().map(|(_, b)| *b).sum();
        let sum_of_commitments: G1Projective = values_and_blindings
            .into_iter()
            .map(|(a, b)| committer.commit(a, b))
            .sum();

        assert_eq!(sum_of_commitments, committer.commit(sum_a, sum_b));
    }

    #[quickcheck]
    fn prop_from_reveal_eq_commit(value: u64, blinding: u64) {
        let value = Scalar::from(value);
        let blinding = Scalar::from(blinding);

        let committer = PedersenCommitter::default();

        let revealed = RevealedCommitment { value, blinding };
        assert_eq!(
            committer.commit(value, blinding),
            committer.from_reveal(revealed)
        );
    }
}
