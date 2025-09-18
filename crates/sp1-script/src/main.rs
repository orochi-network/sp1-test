use std::time::Instant;

use merkle::{traits::Merkle, MerkleTree};
use sp1_sdk::{
    include_elf, utils, ProverClient, SP1ProofWithPublicValues, SP1Stdin,
};
use sp1_util::HashableString;

/// The ELF we want to execute inside the zkVM.
const REGEX_IO_ELF: &[u8] = include_elf!("merkle-program");

fn main() {
    // Setup a tracer for logging.
    utils::setup_logger();

    let mut merkle_tree = MerkleTree::<Vec<u8>, HashableString>::new(128);

    // Create a new stdin with d the input for the program.
    let mut stdin = SP1Stdin::new();

    for i in 0..10 {
        merkle_tree.set_leaf(i as u128, &HashableString::from(i));
    }

    let merkle_proof = merkle_tree.get_merkle_proof(0);

    // Write in a simple regex pattern.
    stdin.write(&merkle_proof);

    // Generate the proof for the given program and input.
    let client = ProverClient::from_env();
    let (pk, vk) = client.setup(REGEX_IO_ELF);

    // start timing
    let start = Instant::now();
    let mut proof = client.prove(&pk, &stdin).run().expect("proving failed");

    println!("Proving took {} ms", start.elapsed().as_millis());

    // Read the output.
    let res = proof.public_values.read::<bool>();
    println!("res: {}", res);

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Test a round trip of proof serialization and deserialization.
    proof
        .save("proof-with-pis.bin")
        .expect("saving proof failed");
    let deserialized_proof =
        SP1ProofWithPublicValues::load("proof-with-pis.bin").expect("loading proof failed");

    // Verify the deserialized proof.
    client
        .verify(&deserialized_proof, &vk)
        .expect("verification failed");

    println!("successfully generated and verified proof for the program!")
}
