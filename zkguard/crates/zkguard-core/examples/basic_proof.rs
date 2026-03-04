//! Basic STARK proof: prove Fibonacci computation

use zkguard::stark::air::SimpleAir;
use zkguard::stark::StarkProver;

fn main() {
    let prover = StarkProver::new(SimpleAir::fibonacci()).expect("prover init failed");
    let proof = prover.prove_fibonacci(8).expect("proof failed");

    println!(
        "Proof generated: {} rows, {} public values",
        proof.num_rows,
        proof.public_values.len()
    );
    println!(
        "F(6) = {}, F(7) = {}",
        proof.public_values[2], proof.public_values[3]
    );

    let verifier = prover.get_verifier();
    let valid = verifier.verify_fibonacci(&proof).expect("verify failed");
    println!("Proof valid: {valid}");
    assert!(valid);
}
