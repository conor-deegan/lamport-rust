use std::env;

use lamport::{generate_keypair, sign, verify, Signature};
use sha256::sha256;

/// Returns the first `len` characters of a hex string followed by "...",
/// or the full string if it's already short enough.
fn truncated_hex(hex: &str, len: usize) -> String {
    if hex.len() <= len {
        hex.to_string()
    } else {
        format!("{}...", &hex[..len])
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let message = if args.len() > 1 {
        args[1].clone()
    } else {
        eprintln!("Usage: {} <message>", args[0]);
        eprintln!("Example: {} \"Hello, World!\"", args[0]);
        std::process::exit(1);
    };

    println!("═══════════════════════════════════════════════════════════");
    println!("                LAMPORT SIGNATURE DEMO");
    println!("═══════════════════════════════════════════════════════════");
    println!();

    // Display message
    println!("MESSAGE");
    println!("───────────────────────────────────────────────────────────");
    println!("\"{}\"", message);
    println!();

    // Hash message
    let message_bytes = message.as_bytes();
    let message_hash = sha256(message_bytes);
    println!("MESSAGE HASH (SHA-256)");
    println!("───────────────────────────────────────────────────────────");
    println!("{}", message_hash.to_hex());
    println!();

    // Generate keypair
    println!("KEY GENERATION");
    println!("───────────────────────────────────────────────────────────");
    let (private_key, public_key) = generate_keypair();
    println!("Private Key: 16,384 bytes (256 pairs x 2 x 32 bytes)");
    println!("Public Key:  16,384 bytes (256 pairs x 2 x 32 bytes)");
    println!();
    let pk_hex = public_key.to_hex();
    println!("Public Key (hex, truncated):");
    println!("  {}", truncated_hex(&pk_hex, 64));
    println!();

    // Sign
    println!("SIGNING");
    println!("───────────────────────────────────────────────────────────");
    let signature = sign(&private_key, message_bytes);
    println!("Signature: 8,192 bytes (256 x 32 bytes)");
    println!();
    let sig_hex = signature.to_hex();
    println!("Signature (hex, truncated):");
    println!("  {}", truncated_hex(&sig_hex, 64));
    println!();

    // Verify
    println!("VERIFICATION");
    println!("───────────────────────────────────────────────────────────");
    let is_valid = verify(&public_key, message_bytes, &signature);
    if is_valid {
        println!("✓ Signature is VALID");
    } else {
        println!("✗ Signature is INVALID");
    }
    println!();

    // Tamper test
    println!("TAMPER TEST");
    println!("───────────────────────────────────────────────────────────");
    let tampered_message = format!("{}!", message);
    let is_valid_tampered = verify(&public_key, tampered_message.as_bytes(), &signature);
    if !is_valid_tampered {
        println!("✓ Tampered message correctly rejected");
    } else {
        println!("✗ ERROR: Tampered message was accepted!");
    }

    println!();
    println!();
    println!("═══════════════════════════════════════════════════════════");
    println!("                KEY REUSE ATTACK");
    println!("═══════════════════════════════════════════════════════════");
    println!();
    println!("Each signature reveals 256 of the 512 private key values.");
    println!("By observing multiple signatures, an attacker can recover");
    println!("the ENTIRE private key and forge arbitrary signatures.");
    println!();

    // A Lamport private key has 256 pairs of 32-byte secrets (512 values total).
    // Each signature reveals exactly one value per pair (256 of the 512), chosen by
    // the corresponding bit of the message hash. If the signer reuses the key, an
    // attacker who sees multiple signatures can collect both values for each pair.
    // Once all 512 are known, the attacker has the full private key and can forge
    // a valid signature on any message.
    let (attack_sk, attack_pk) = generate_keypair();

    // The public key bytes are laid out as: [pair_0_slot_0 (32B), pair_0_slot_1 (32B), pair_1_slot_0, ...]
    // We use this to identify which slot each signature value belongs to.
    let pk_bytes = attack_pk.to_bytes();

    // The attacker's recovered key buffer mirrors the private key byte layout.
    // `known[i]` tracks whether slot `i` (of 512) has been recovered yet.
    let mut recovered = vec![0u8; 256 * 2 * 32];
    let mut known = vec![false; 512];
    let mut num_recovered: usize = 0;

    println!("RECOVERING PRIVATE KEY");
    println!("───────────────────────────────────────────────────────────");
    println!("Attacker observes signatures on different messages...");
    println!();

    // Sign messages until the full private key is recovered
    let mut num_signatures = 0;
    while num_recovered < 512 {
        num_signatures += 1;
        let msg = format!("Reused key message #{}", num_signatures);
        let sig = sign(&attack_sk, msg.as_bytes());
        let sig_bytes = sig.to_bytes();

        // The attacker doesn't know which bit of the message hash selected each
        // signature value, but they don't need to — they can just hash each value
        // with SHA-256 and compare against both public key slots for that position.
        // Whichever slot matches tells them which private key value was revealed:
        //   SHA-256(sig_value) == pk_slot_0  →  this is private_key[i][0]
        //   SHA-256(sig_value) == pk_slot_1  →  this is private_key[i][1]
        for i in 0..256 {
            let sig_value = &sig_bytes[i * 32..(i + 1) * 32];
            let hash_of_sig = sha256(sig_value);

            let pk_slot_0 = &pk_bytes[i * 64..i * 64 + 32];
            let pk_slot_1 = &pk_bytes[i * 64 + 32..i * 64 + 64];

            if !known[i * 2] && hash_of_sig.as_bytes()[..] == pk_slot_0[..] {
                known[i * 2] = true;
                recovered[i * 64..i * 64 + 32].copy_from_slice(sig_value);
                num_recovered += 1;
            } else if !known[i * 2 + 1] && hash_of_sig.as_bytes()[..] == pk_slot_1[..] {
                known[i * 2 + 1] = true;
                recovered[i * 64 + 32..i * 64 + 64].copy_from_slice(sig_value);
                num_recovered += 1;
            }
        }

        println!(
            "  Signature {:>2}: {}/512 private key values recovered ({:.1}%)",
            num_signatures,
            num_recovered,
            num_recovered as f64 / 512.0 * 100.0,
        );
    }

    println!();
    println!(
        "  Full private key recovered after {} signatures!",
        num_signatures
    );
    println!();

    // Now the attacker forges a signature on a message the real signer never signed.
    // A valid Lamport signature for message M is: for each bit i of SHA-256(M),
    // reveal private_key[i][bit]. Since we've recovered all 512 values, we can
    // construct this for any message.
    let forged_msg = b"Send all funds to the attacker";
    let forged_hash = sha256(forged_msg).0;

    let mut forged_sig_bytes = vec![0u8; 256 * 32];
    for i in 0..256 {
        // Extract bit i from the hash (MSB-first, same convention as the lamport crate).
        let bit = (forged_hash[i / 8] >> (7 - (i % 8))) & 1;
        // Pick the matching recovered private key value for this bit.
        let src = i * 64 + (bit as usize) * 32;
        let dst = i * 32;
        forged_sig_bytes[dst..dst + 32].copy_from_slice(&recovered[src..src + 32]);
    }
    let forged_sig = Signature::from_bytes(&forged_sig_bytes).unwrap();

    println!("FORGING SIGNATURE");
    println!("───────────────────────────────────────────────────────────");
    println!("Target message: \"Send all funds to the attacker\"");
    println!();

    let forged_valid = verify(&attack_pk, forged_msg, &forged_sig);
    if forged_valid {
        println!("✓ FORGED signature is VALID");
        println!("  The attacker can now sign ANY message with this key!");
    } else {
        println!("✗ Forgery failed (unexpected)");
    }

    println!();
    println!("═══════════════════════════════════════════════════════════");
}
