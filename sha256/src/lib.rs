/// Initial hash values: first 32 bits of the fractional parts of the square roots of the first 8 primes.
const H: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Rotates a 32-bit word `x` to the right by `n` positions. Bits that fall off the right
/// end wrap around to the left. For example, rotr(0b11010000..., 2) moves every bit two
/// places right, and the two lowest bits become the two highest bits.
fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

/// "Choose": for each bit position, if the bit in `x` is 1, pick the corresponding bit
/// from `y`; if the bit in `x` is 0, pick the corresponding bit from `z`. So `x` acts as
/// a selector that chooses between `y` and `z` on a per-bit basis.
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// "Majority": for each bit position, returns the value that appears in at least two of the
/// three inputs. If two or more of `x`, `y`, `z` have a 1 at a given position, the result
/// has a 1 there; otherwise it has a 0.
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Big Sigma 0 (Σ0): takes a word, rotates it right by 2, 13, and 22 positions separately,
/// then XORs those three rotated copies together. Used in the compression loop to mix bits
/// of the `a` working variable. The three different rotation amounts ensure that every input
/// bit influences many output bit positions.
fn big_sigma0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

/// Big Sigma 1 (Σ1): takes a word, rotates it right by 6, 11, and 25 positions separately,
/// then XORs those three rotated copies together. Used in the compression loop to mix bits
/// of the `e` working variable.
fn big_sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

/// Small sigma 0 (σ0): rotates right by 7, rotates right by 18, and shifts right by 3
/// (the shift discards the lowest 3 bits instead of wrapping them). XORs all three results
/// together. Used in the message schedule to derive words 16..63 from earlier words.
fn small_sigma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

/// Small sigma 1 (σ1): rotates right by 17, rotates right by 19, and shifts right by 10,
/// then XORs all three results. Also used in the message schedule alongside σ0 to expand
/// the 16 input words into 64 schedule words.
fn small_sigma1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

/// Pads the message so its total length is a multiple of 64 bytes (512 bits), which is the
/// block size SHA-256 operates on. The padding works in three steps:
/// 1. Append a single 0x80 byte (a 1-bit followed by seven 0-bits).
/// 2. Append as many 0x00 bytes as needed until the length is 8 bytes short of a 64-byte boundary.
/// 3. Append the original message length in bits as an 8-byte big-endian integer.
/// This ensures the receiver can always tell where the real message ends and padding begins.
fn pad_message(message: &[u8]) -> Vec<u8> {
    let original_len_bits = (message.len() as u64) * 8;
    let mut padded = message.to_vec();

    // Append 0x80 (bit '1' followed by seven '0' bits)
    padded.push(0x80);

    // Append zeros until length in bytes ≡ 56 (mod 64)
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }

    // Append original length as 64-bit big-endian
    padded.extend_from_slice(&original_len_bits.to_be_bytes());

    padded
}

/// Takes a single 64-byte (512-bit) block and expands it into 64 32-bit words. The first 16
/// words are just the block split into 32-bit big-endian chunks. Words 16 through 63 are each
/// computed from four earlier words: w[i] = σ1(w[i-2]) + w[i-7] + σ0(w[i-15]) + w[i-16].
/// This spreads the influence of every input byte across many words so that the compression
/// step has richer material to work with in each of its 64 rounds.
fn create_message_schedule(block: &[u8]) -> [u32; 64] {
    let mut w = [0u32; 64];

    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    for i in 16..64 {
        w[i] = small_sigma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(small_sigma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    w
}

/// Runs 64 rounds of mixing on the 8-word hash state using the 64-word message schedule.
/// Copies the state into working variables a..h, then for each round: computes two temporary
/// values t1 and t2 from the working variables, the round constant K[i], and the schedule
/// word w[i]; shifts every variable down one slot (h=g, g=f, ...); and inserts the new
/// values at a and e. After all 64 rounds, adds the working variables back into the original
/// state. This addition is what makes the function one-way — you can't subtract back out
/// without knowing the working variables at each step.
fn compress(state: &mut [u32; 8], w: &[u32; 64]) {
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// A SHA-256 hash (32 bytes). Use [Sha256::to_hex] for a hex string.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sha256(pub [u8; 32]);

impl Sha256 {
    /// Returns the hash as a lowercase hex string (64 characters).
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Returns the raw 32-byte hash.
    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for Sha256 {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Takes an arbitrary-length byte slice and produces a 256-bit (32-byte) hash. First pads the
/// message to a multiple of 64 bytes, then processes each 64-byte block by building a message
/// schedule and compressing it into the running state. The state starts as the eight fixed
/// initial hash values H. After all blocks are processed, the final state is serialized into
/// 32 bytes as the hash output.
pub fn sha256(message: &[u8]) -> Sha256 {
    let padded = pad_message(message);
    let mut state = H;

    for block in padded.chunks(64) {
        let w = create_message_schedule(block);
        compress(&mut state, &w);
    }

    let mut result = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }

    Sha256(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string() {
        assert_eq!(
            sha256(b"").to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            sha256(b"abc").to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn two_block_message() {
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_hex(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn million_a() {
        let input = vec![b'a'; 1_000_000];
        assert_eq!(
            sha256(&input).to_hex(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn exactly_56_bytes() {
        let input = vec![b'x'; 56];
        assert_eq!(sha256(&input).as_bytes().len(), 32);
    }

    #[test]
    fn exactly_64_bytes() {
        let input = vec![b'x'; 64];
        assert_eq!(sha256(&input).as_bytes().len(), 32);
    }
}
