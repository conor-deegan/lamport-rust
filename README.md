# Lamport and SHA-256 from Scratch

SHA-256 and Lamport one-time signatures implemented from scratch in Rust. No cryptographic dependencies — only `rand` for key generation and `hex` for pretty printing stuff.

## Workspace

| Crate | Description |
|-------|-------------|
| `sha256` | SHA-256 hash function (padding, message schedule, compression — all from the spec) |
| `lamport` | Lamport one-time signature scheme (keygen, sign, verify) built on `sha256` |
| `cli` | Interactive demo: hash, sign, verify, tamper detection, and a key-reuse attack |

## Run the demo

```
cargo run --bin cli "your message here"
```

This will:
1. Hash your message with SHA-256
2. Generate a Lamport keypair
3. Sign the message and verify the signature
4. Tamper with the message and show verification fails
5. Demonstrate a **key-reuse attack** — reusing a Lamport key across multiple messages leaks private key material until an attacker can recover the full key and forge signatures

## Run the tests

```
cargo test --workspace
```
