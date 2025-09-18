pub use blake3::{Hash, Hasher};
use merkle::traits::Hashable;
pub use merkle::MerkleProof;

#[derive(Debug)]
pub struct HashableString(String);

impl Hashable<Vec<u8>> for HashableString {
    fn zero() -> Self {
        HashableString(String::new())
    }

    fn hash(&self) -> Vec<u8> {
        Hasher::new()
            .update(self.0.as_bytes())
            .finalize()
            .as_bytes()
            .to_vec()
    }

    fn compose_hash(left: &Vec<u8>, right: &Vec<u8>) -> Vec<u8> {
        Hasher::new()
            .update(left)
            .update(right)
            .finalize()
            .as_bytes()
            .to_vec()
    }
}

impl From<i32> for HashableString {
    fn from(value: i32) -> Self {
        Self(value.to_string())
    }
}
