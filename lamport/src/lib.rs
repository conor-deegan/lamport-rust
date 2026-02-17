use rand::RngCore;
use sha256::sha256;

/// Private key: 256 pairs of 256-bit random values.
/// `pairs[i][0]` is revealed if bit `i` of the message hash is 0.
/// `pairs[i][1]` is revealed if bit `i` of the message hash is 1.
///
/// **Warning:** A Lamport private key must only be used to sign ONE message.
/// Signing multiple messages reveals additional private key material and compromises security.
pub struct PrivateKey {
    pairs: [[[u8; 32]; 2]; 256],
}

/// Public key: 256 pairs of SHA-256 hashes derived from the private key.
/// `pairs[i][j] = SHA-256(private_key.pairs[i][j])`
///
/// To pass the public key around: use [PublicKey::to_bytes] / [PublicKey::from_bytes] for
/// binary, or [PublicKey::to_hex] / [PublicKey::from_hex] for a hex string (e.g. config, API).
pub struct PublicKey {
    pairs: [[[u8; 32]; 2]; 256],
}

/// Signature: 256 revealed private key values, one per bit of the message hash.
pub struct Signature {
    values: [[u8; 32]; 256],
}

/// Extracts one bit from the 32-byte hash for use in the Lamport scheme.
///
/// Bits are numbered 0..255 in big-endian order: the first byte's high bit is bit 0,
/// its next bit is bit 1, … and the last byte's low bit is bit 255.
///
/// Example: if `hash[0] = 0x80` (binary 10000000), then with MSB-first numbering
/// `get_bit(hash, 0)` = 1 and `get_bit(hash, 1..8)` = 0. With LSB-first it would be the opposite.
fn get_bit(hash: &[u8; 32], bit_index: usize) -> u8 {
    let byte_index = bit_index / 8;           // which of the 32 bytes (0..31)
    let bit_position = 7 - (bit_index % 8);   // which bit within that byte (0 = MSB, 7 = LSB)
    (hash[byte_index] >> bit_position) & 1    // shift then mask to 0 or 1
}

/// Generates a new Lamport keypair.
///
/// The private key consists of 256 pairs of cryptographically random 256-bit values.
/// The public key is the SHA-256 hash of each private key component.
pub fn generate_keypair() -> (PrivateKey, PublicKey) {
    let mut rng = rand::thread_rng();
    let mut private_key = PrivateKey {
        pairs: [[[0u8; 32]; 2]; 256],
    };
    let mut public_key = PublicKey {
        pairs: [[[0u8; 32]; 2]; 256],
    };

    for i in 0..256 {
        rng.fill_bytes(&mut private_key.pairs[i][0]);
        rng.fill_bytes(&mut private_key.pairs[i][1]);

        public_key.pairs[i][0] = sha256(&private_key.pairs[i][0]).0;
        public_key.pairs[i][1] = sha256(&private_key.pairs[i][1]).0;
    }

    (private_key, public_key)
}

/// Signs a message with a Lamport private key.
///
/// The message is first hashed with SHA-256 to produce 256 bits. For each bit `i`,
/// the signature reveals `private_key.pairs[i][bit]` where `bit` is the value of bit `i`
/// in the hash.
///
/// **Warning:** Each private key must only be used to sign ONE message.
pub fn sign(private_key: &PrivateKey, message: &[u8]) -> Signature {
    let message_hash = sha256(message).0;
    let mut signature = Signature {
        values: [[0u8; 32]; 256],
    };

    for i in 0..256 {
        let bit = get_bit(&message_hash, i);
        signature.values[i] = private_key.pairs[i][bit as usize];
    }

    signature
}

/// Verifies a Lamport signature against a public key and message.
///
/// For each bit `i` of the message hash, hashes `signature.values[i]` and checks
/// that it matches `public_key.pairs[i][bit]`. Returns `true` only if all 256
/// values match.
pub fn verify(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    let message_hash = sha256(message).0;

    for i in 0..256 {
        let bit = get_bit(&message_hash, i);
        let computed_hash = sha256(&signature.values[i]).0;

        if computed_hash != public_key.pairs[i][bit as usize] {
            return false;
        }
    }

    true
}

impl PrivateKey {
    /// Serializes the private key to bytes (16,384 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256 * 2 * 32);
        for pair in &self.pairs {
            bytes.extend_from_slice(&pair[0]);
            bytes.extend_from_slice(&pair[1]);
        }
        bytes
    }

    /// Deserializes a private key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 256 * 2 * 32 {
            return Err("invalid private key length: expected 16384 bytes");
        }
        let mut key = PrivateKey {
            pairs: [[[0u8; 32]; 2]; 256],
        };
        for i in 0..256 {
            let offset = i * 64;
            key.pairs[i][0].copy_from_slice(&bytes[offset..offset + 32]);
            key.pairs[i][1].copy_from_slice(&bytes[offset + 32..offset + 64]);
        }
        Ok(key)
    }

    /// Returns the private key as a full lowercase hex string (32,768 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Deserializes a private key from a hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, &'static str> {
        let bytes = hex::decode(hex_str).map_err(|_| "invalid hex")?;
        Self::from_bytes(&bytes)
    }
}

impl PublicKey {
    /// Serializes the public key to bytes (16,384 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256 * 2 * 32);
        for pair in &self.pairs {
            bytes.extend_from_slice(&pair[0]);
            bytes.extend_from_slice(&pair[1]);
        }
        bytes
    }

    /// Deserializes a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 256 * 2 * 32 {
            return Err("invalid public key length: expected 16384 bytes");
        }
        let mut key = PublicKey {
            pairs: [[[0u8; 32]; 2]; 256],
        };
        for i in 0..256 {
            let offset = i * 64;
            key.pairs[i][0].copy_from_slice(&bytes[offset..offset + 32]);
            key.pairs[i][1].copy_from_slice(&bytes[offset + 32..offset + 64]);
        }
        Ok(key)
    }

    /// Returns the public key as a full lowercase hex string (32,768 characters).
    /// Use with [PublicKey::from_hex] to pass the key as text (e.g. config, API).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Deserializes a public key from a hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, &'static str> {
        let bytes = hex::decode(hex_str).map_err(|_| "invalid hex")?;
        Self::from_bytes(&bytes)
    }
}

impl Signature {
    /// Serializes the signature to bytes (8,192 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256 * 32);
        for value in &self.values {
            bytes.extend_from_slice(value);
        }
        bytes
    }

    /// Deserializes a signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 256 * 32 {
            return Err("invalid signature length: expected 8192 bytes");
        }
        let mut sig = Signature {
            values: [[0u8; 32]; 256],
        };
        for i in 0..256 {
            let offset = i * 32;
            sig.values[i].copy_from_slice(&bytes[offset..offset + 32]);
        }
        Ok(sig)
    }

    /// Returns the signature as a full lowercase hex string (16,384 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Deserializes a signature from a hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, &'static str> {
        let bytes = hex::decode(hex_str).map_err(|_| "invalid hex")?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let (private_key, public_key) = generate_keypair();
        let message = b"Hello, Lamport!";
        let signature = sign(&private_key, message);
        assert!(verify(&public_key, message, &signature));
    }

    #[test]
    fn test_wrong_message_fails() {
        let (private_key, public_key) = generate_keypair();
        let message = b"Hello, Lamport!";
        let signature = sign(&private_key, message);
        assert!(!verify(&public_key, b"Wrong message", &signature));
    }

    #[test]
    fn test_wrong_key_fails() {
        let (private_key, _) = generate_keypair();
        let (_, other_public_key) = generate_keypair();
        let message = b"Hello, Lamport!";
        let signature = sign(&private_key, message);
        assert!(!verify(&other_public_key, message, &signature));
    }

    #[test]
    fn test_empty_message() {
        let (private_key, public_key) = generate_keypair();
        let message = b"";
        let signature = sign(&private_key, message);
        assert!(verify(&public_key, message, &signature));
    }

    #[test]
    fn test_long_message() {
        let (private_key, public_key) = generate_keypair();
        let message = vec![0xAB; 10000];
        let signature = sign(&private_key, &message);
        assert!(verify(&public_key, &message, &signature));
    }

    #[test]
    fn test_get_bit() {
        // 0xA5 = 0b10100101
        let mut hash = [0u8; 32];
        hash[0] = 0xA5;
        assert_eq!(get_bit(&hash, 0), 1); // MSB
        assert_eq!(get_bit(&hash, 1), 0);
        assert_eq!(get_bit(&hash, 2), 1);
        assert_eq!(get_bit(&hash, 3), 0);
        assert_eq!(get_bit(&hash, 4), 0);
        assert_eq!(get_bit(&hash, 5), 1);
        assert_eq!(get_bit(&hash, 6), 0);
        assert_eq!(get_bit(&hash, 7), 1); // LSB
    }

    #[test]
    fn test_serialization_roundtrip_private_key() {
        let (private_key, _) = generate_keypair();
        let bytes = private_key.to_bytes();
        assert_eq!(bytes.len(), 16384);
        let restored = PrivateKey::from_bytes(&bytes).unwrap();
        assert_eq!(private_key.pairs, restored.pairs);
    }

    #[test]
    fn test_serialization_roundtrip_public_key() {
        let (_, public_key) = generate_keypair();
        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), 16384);
        let restored = PublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(public_key.pairs, restored.pairs);
    }

    #[test]
    fn test_serialization_roundtrip_signature() {
        let (private_key, _) = generate_keypair();
        let signature = sign(&private_key, b"test");
        let bytes = signature.to_bytes();
        assert_eq!(bytes.len(), 8192);
        let restored = Signature::from_bytes(&bytes).unwrap();
        assert_eq!(signature.values, restored.values);
    }

    #[test]
    fn test_invalid_bytes_length() {
        assert!(PrivateKey::from_bytes(&[0u8; 100]).is_err());
        assert!(PublicKey::from_bytes(&[0u8; 100]).is_err());
        assert!(Signature::from_bytes(&[0u8; 100]).is_err());
    }

    #[test]
    fn test_hex_roundtrip_private_key() {
        let (private_key, _) = generate_keypair();
        let hex_str = private_key.to_hex();
        assert_eq!(hex_str.len(), 32768);
        let restored = PrivateKey::from_hex(&hex_str).unwrap();
        assert_eq!(private_key.pairs, restored.pairs);
    }

    #[test]
    fn test_hex_roundtrip_public_key() {
        let (_, public_key) = generate_keypair();
        let hex_str = public_key.to_hex();
        assert_eq!(hex_str.len(), 32768);
        let restored = PublicKey::from_hex(&hex_str).unwrap();
        assert_eq!(public_key.pairs, restored.pairs);
    }

    #[test]
    fn test_hex_roundtrip_signature() {
        let (private_key, _) = generate_keypair();
        let signature = sign(&private_key, b"test");
        let hex_str = signature.to_hex();
        assert_eq!(hex_str.len(), 16384);
        let restored = Signature::from_hex(&hex_str).unwrap();
        assert_eq!(signature.values, restored.values);
    }

    #[test]
    fn test_from_hex_invalid() {
        assert!(PrivateKey::from_hex("zz").is_err());
        assert!(PublicKey::from_hex("ab").is_err()); // wrong length after decode
    }
}
