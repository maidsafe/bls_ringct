use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum Error {
    #[error("We need a corresponding public key for each MLSAG ring entry")]
    ExpectedAPublicCommitmentsForEachRingEntry,
    #[error("The hidden commitment in the MLSAG ring must be of the form: $C - C'$")]
    InvalidHiddenCommitmentInRing,
    #[error("InputPseudoCommitmentsDoNotSumToOutputCommitments")]
    InputPseudoCommitmentsDoNotSumToOutputCommitments,
    #[error("The MLSAG ring signature is not valid")]
    InvalidRingSignature,
    #[error("KeyImage is not on the BLS12-381 G1 Curve")]
    KeyImageNotOnCurve,
    #[error("BulletProofs Error: {0}")]
    BulletProofs(#[from] bulletproofs::ProofError),
    #[error("The DBC transaction must have at least one input")]
    TransactionMustHaveAnInput,
    #[error("key image is not unique across all transaction inputs")]
    KeyImageNotUniqueAcrossInputs,
    #[error("public key is not unique across all transaction inputs")]
    PublicKeyNotUniqueAcrossInputs,
}
