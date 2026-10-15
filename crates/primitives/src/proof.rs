//! Proof-related types used across the bridge.

use strata_identifiers::L1BlockCommitment;
use strata_predicate::{PredicateKey, PredicateTypeId};
use zkaleido::ProofReceipt;

/// Returns `true` if the proof is valid according to the given predicate key.
///
/// `AlwaysAccept` is not a verification. Its verifier returns success for every witness, including
/// an empty one, so a receipt that names the expected claim can set `total_pow` above any real
/// chain and the heavier-chain check finds nothing to challenge.
pub fn verify_bridge_proof(predicate_key: &PredicateKey, proof: &ProofReceipt) -> bool {
    if predicate_key.id() == PredicateTypeId::AlwaysAccept.as_u8() {
        return false;
    }
    predicate_key
        .verify_claim_witness(proof.public_values().as_bytes(), proof.proof().as_bytes())
        .is_ok()
}

/// An opaque ASM step proof for a range of L1 blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsmProof(pub Vec<u8>);

/// An opaque Moho recursive proof, valid up to some L1 block commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MohoProof(pub Vec<u8>);

/// A range of L1 blocks defined by start and end commitments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct L1Range {
    /// The start of the range (inclusive).
    start: L1BlockCommitment,
    /// The end of the range (inclusive).
    end: L1BlockCommitment,
}

impl L1Range {
    /// Creates a new `L1Range` from start and end commitments.
    ///
    /// Returns `None` if `end` height is strictly less than `start` height.
    pub fn new(start: L1BlockCommitment, end: L1BlockCommitment) -> Option<Self> {
        if end.height() < start.height() {
            return None;
        }
        Some(Self { start, end })
    }

    /// Creates a range that covers a single block (start == end).
    pub const fn single(block: L1BlockCommitment) -> Self {
        Self {
            start: block,
            end: block,
        }
    }

    /// Returns the start of the range.
    pub const fn start(&self) -> L1BlockCommitment {
        self.start
    }

    /// Returns the end of the range.
    pub const fn end(&self) -> L1BlockCommitment {
        self.end
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::{sha256, Hash};
    use secp256k1::{Keypair, Message, Secp256k1};
    use strata_predicate::PredicateTypeId;
    use zkaleido::{Proof, PublicValues};

    use super::*;

    fn receipt(witness: Vec<u8>, claim: Vec<u8>) -> ProofReceipt {
        ProofReceipt::new(Proof::new(witness), PublicValues::new(claim))
    }

    #[test]
    fn always_accept_does_not_verify_a_bridge_proof() {
        let proof = receipt(vec![], vec![0xff; 32]);
        assert!(!verify_bridge_proof(&PredicateKey::always_accept(), &proof));
        let with_condition =
            PredicateKey::try_new(PredicateTypeId::AlwaysAccept, vec![0xff]).unwrap();
        assert!(!verify_bridge_proof(&with_condition, &proof));
    }

    #[test]
    fn schnorr_predicate_verifies_only_its_witness() {
        // k256's Verifier hashes the claim with SHA-256, then checks BIP340 over that digest.
        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[0x11; 32]).unwrap();
        let claim = b"bridge-proof-claim".to_vec();
        let digest: [u8; 32] = sha256::Hash::hash(&claim).to_byte_array();
        let sig = secp.sign_schnorr(&Message::from_digest(digest), &keypair);
        let predicate = PredicateKey::try_new(
            PredicateTypeId::Bip340Schnorr,
            keypair.x_only_public_key().0.serialize().to_vec(),
        )
        .unwrap();

        assert!(verify_bridge_proof(
            &predicate,
            &receipt(sig.as_ref().to_vec(), claim.clone())
        ));
        let mut other = claim.clone();
        other[0] ^= 1;
        assert!(!verify_bridge_proof(
            &predicate,
            &receipt(sig.as_ref().to_vec(), other)
        ));
        assert!(!verify_bridge_proof(
            &PredicateKey::never_accept(),
            &receipt(sig.as_ref().to_vec(), claim)
        ));
    }
}
