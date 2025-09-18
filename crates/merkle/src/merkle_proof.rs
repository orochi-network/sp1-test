use crate::traits::{Hashable, Witness};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, marker::PhantomData};

#[derive(Debug, Serialize, Deserialize)]
pub struct MerkleProof<T, V> {
    pub leaf: T,
    pub root: T,
    pub witness: Vec<Witness<T>>,
    _phantom: PhantomData<V>,
}

impl<T: Clone + Eq + Debug, V: Hashable<T>> MerkleProof<T, V> {
    pub fn new(leaf: T, root: T, witness: Vec<Witness<T>>) -> Self {
        MerkleProof {
            leaf,
            root,
            witness,
            _phantom: PhantomData,
        }
    }

    pub fn is_valid(&self) -> bool {
        let mut computed_hash = self.leaf.clone();
        for w in &self.witness {
            computed_hash = match w {
                Witness::Left(sibling) => V::compose_hash(&computed_hash, sibling),
                Witness::Right(sibling) => V::compose_hash(sibling, &computed_hash),
            };
        }
        computed_hash == self.root
    }
}
