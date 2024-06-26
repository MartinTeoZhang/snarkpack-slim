
use ark_ec::{pairing::Pairing };
// {AffineCurve, PairingEngine, ProjectiveCurve};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};



/// Maximum size of the generic SRS constructed from Filecoin and Zcash power of
/// taus.
///
/// https://github.com/nikkolasg/taupipp/blob/baca1426266bf39416c45303e35c966d69f4f8b4/src/bin/assemble.rs#L12
pub const MAX_SRS_SIZE: usize = (2 << 19) + 1;


/// Contains the necessary elements to verify an aggregated Groth16 proof; it is of fixed size
/// regardless of the number of proofs aggregated. However, a verifier SRS will be determined by
/// the number of proofs being aggregated.
#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct VerifierSRS<E: Pairing> {
    pub n: usize,
    pub g: E::G1,
    pub h: E::G2,
    pub g_alpha: E::G1,
    pub g_beta: E::G1,
    pub h_alpha: E::G2,
    pub h_beta: E::G2,
}

