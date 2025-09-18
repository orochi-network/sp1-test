//! A simple program that takes a regex pattern and a string and returns whether the string
//! matches the pattern.
#![no_main]
sp1_zkvm::entrypoint!(main);
use sp1_util::{HashableString, MerkleProof};

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.

pub fn main() {
    // Read two inputs from the prover: a regex pattern and a target string.
    let merkle_proof = sp1_zkvm::io::read::<MerkleProof<Vec<u8>, HashableString>>();

    // Perform the regex search on the target string.
    let result = merkle_proof.is_valid();

    // Write the result (true or false) to the output.
    sp1_zkvm::io::commit(&result);
}
