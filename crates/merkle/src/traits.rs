use serde::{Deserialize, Serialize};

use crate::MerkleProof;

/// Witnesses are used in the Merkle tree implementation
/// to represent the path from a leaf node to the root node.
#[derive(Debug, Serialize, Deserialize)]
pub enum Witness<T> {
    Left(T),
    Right(T),
}

/// A trait that determines how to hash a value. This trait is used in the Merkle tree implementation.
/// Any thing that implements this trait can be used as a hashable value in the Merkle tree.
///
/// # Examples
/// ```rust
/// use merkle::Hashable;
///
/// struct HashableString(String);
///
/// impl Hashable<Hash> for HashableString {
///    fn zero() -> Self {
///        HashableString(String::from(""))
///    }
///
///    fn hash(&self) -> Hash {
///        let mut hasher = Hasher::new();
///        hasher.update(self.0.as_bytes());
///        hasher.finalize()
///    }
///
///    fn compose_hash(left: &Hash, right: &Hash) -> Hash {
///        let mut hasher = Hasher::new();
///        hasher.update(left.as_bytes());
///        hasher.update(right.as_bytes());
///        hasher.finalize()
///    }
/// }
/// ```
/// Follow the example to create a custom hashable type. This will allow you to use your own types
/// in the Merkle tree implementation.
pub trait Hashable<T> {
    fn zero() -> Self;

    fn hash(&self) -> T;

    fn compose_hash(left: &T, right: &T) -> T;
}

/// Merkle tree trait that defines the basic operations for a Merkle tree.
pub trait Merkle<T, V: Hashable<T>> {
    /// Create a new Merkle tree with the specified height.
    fn new(heigh: usize) -> Self;

    /// Get the node at a specific level and index.
    fn get_node(&self, level: usize, index: u128) -> &T;

    /// Get the leaf at a specific index.
    fn get_leaf(&self, index: u128) -> &T;

    /// Get the root of the Merkle tree.
    fn get_root(&self) -> &T;

    /// Set the leaf at a specific index.
    fn set_leaf(&mut self, index: u128, leaf: &V);

    /// Get the witness for a specific index.
    fn get_witness(&mut self, index: u128) -> Vec<Witness<T>>;

    /// Get merkle proof for a specific index.
    fn get_merkle_proof(&mut self, index: u128) -> MerkleProof<T, V>;

    /// Get maximum leaf count of the Merkle tree.
    fn leaf_count(&mut self) -> u128;
}
