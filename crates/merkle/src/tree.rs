use crate::traits::{Hashable, Merkle, Witness};
use std::{collections::HashMap, fmt::Debug, marker::PhantomData};

/// Merkle tree struct that implements the Merkle trait.
/// This will allow you to create a Merkle tree
#[derive(Debug)]
pub struct MerkleTree<T, V> {
    height: usize,
    nodes: HashMap<usize, HashMap<u128, T>>,
    zeroes: Vec<T>,
    _phantom: PhantomData<V>,
}

impl<T: Clone + Eq + Debug, V: Hashable<T>> Merkle<T, V> for MerkleTree<T, V> {
    fn new(height: usize) -> Self {
        if !(8..=128).contains(&height) {
            panic!("Invalid height for merkle tree, we're only support 8-128");
        }
        let mut zeroes = Vec::<T>::with_capacity(height);
        zeroes.push(V::zero().hash());
        for i in 1..height {
            zeroes.push(V::compose_hash(&zeroes[i - 1], &zeroes[i - 1]));
        }
        MerkleTree {
            height,
            nodes: HashMap::new(),
            zeroes,
            _phantom: PhantomData,
        }
    }

    fn get_node(&self, level: usize, index: u128) -> &T {
        match self.nodes.get(&level) {
            Some(merkle_level) => match merkle_level.get(&index) {
                Some(merkle_index) => merkle_index,
                None => &self.zeroes[level],
            },
            None => &self.zeroes[level],
        }
    }

    fn get_leaf(&self, index: u128) -> &T {
        self.get_node(0, index)
    }

    fn get_root(&self) -> &T {
        self.get_node(self.height - 1, 0)
    }

    fn set_leaf(&mut self, index: u128, leaf: &V) {
        if index >= self.leaf_count() {
            panic!("Unable to to set leaf index is out of range")
        }
        let mut current_index = index;
        self.set_node(0, index, &leaf.hash());
        for level in 1..self.height {
            current_index /= 2;
            let left = self.get_node(level - 1, current_index * 2);
            let right = self.get_node(level - 1, current_index * 2 + 1);
            self.set_node(level, current_index, &V::compose_hash(left, right));
        }
    }

    fn get_witness(&mut self, index: u128) -> Vec<Witness<T>> {
        if index >= self.leaf_count() {
            panic!("Unable to to set leaf index is out of range")
        }
        let mut witness = Vec::with_capacity(self.height - 1);
        let mut current_index = index;
        for level in 0..self.height - 1 {
            if current_index % 2 == 0 {
                witness.push(Witness::Left(
                    self.get_node(level, current_index + 1).clone(),
                ));
            } else {
                witness.push(Witness::Right(
                    self.get_node(level, current_index - 1).clone(),
                ));
            }
            current_index /= 2;
        }
        witness
    }

    fn get_merkle_proof(&mut self, index: u128) -> crate::MerkleProof<T, V> {
        let leaf = self.get_leaf(index).clone();
        let root = self.get_root().clone();

        let witness = self.get_witness(index);

        crate::MerkleProof::new(leaf, root, witness)
    }

    fn leaf_count(&mut self) -> u128 {
        1 << (self.height - 1)
    }
}

impl<T: Clone + Eq + Debug, V: Hashable<T>> MerkleTree<T, V> {
    /// Set a node in the Merkle tree. This will panic if the index is out of range.
    fn set_node(&mut self, level: usize, index: u128, hash: &T) {
        match self.nodes.get_mut(&level) {
            Some(merkle_level) => {
                merkle_level.insert(index, hash.clone());
            }
            None => {
                let mut new_hashmap = HashMap::new();
                new_hashmap.insert(index, hash.clone());
                self.nodes.insert(level, new_hashmap);
            }
        }
    }

    /// Verify merkle witness. This will panic if the index is out of range or if the witness is invalid.
    pub fn verify(&self, index: u128, merkle_witness: &Vec<Witness<T>>) -> bool {
        let leaf = self.get_leaf(index);
        let root = self.get_root();

        let mut current = leaf.clone();

        for w in merkle_witness {
            current = match w {
                Witness::Left(h) => V::compose_hash(&current, h),
                Witness::Right(h) => V::compose_hash(h, &current),
            }
        }
        current == *root
    }
}
