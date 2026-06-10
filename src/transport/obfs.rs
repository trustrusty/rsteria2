//! "Salamander" packet obfuscation (Go: extras/obfs/salamander.go).
//!
//! Each QUIC packet is prefixed with a random 8-byte salt and XOR'd with
//! `BLAKE2b-256(PSK || salt)`, repeating the 32-byte key over the payload.
//! Wire format: `[8-byte salt][obfuscated payload]`.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use rand::RngCore;

/// BLAKE2b digest with a 32-byte (256-bit) output, matching Go's `blake2b.Size256`.
type Blake2b256 = Blake2b<U32>;

const SALT_LEN: usize = 8;
const KEY_LEN: usize = 32;
/// Minimum pre-shared key length (Go `smPSKMinLen`).
pub const MIN_PSK_LEN: usize = 4;

/// Salamander obfuscator. Cheap to clone; holds only the PSK.
#[derive(Clone)]
pub struct Salamander {
    psk: Vec<u8>,
}

impl Salamander {
    /// Build an obfuscator from a pre-shared key. Returns `None` if the key is
    /// shorter than [`MIN_PSK_LEN`] (Go returns `ErrPSKTooShort`).
    pub fn new(psk: &[u8]) -> Option<Salamander> {
        if psk.len() < MIN_PSK_LEN {
            return None;
        }
        Some(Salamander { psk: psk.to_vec() })
    }

    fn key(&self, salt: &[u8]) -> [u8; KEY_LEN] {
        let mut h = Blake2b256::new();
        h.update(&self.psk);
        h.update(salt);
        h.finalize().into()
    }

    /// Obfuscate `input` into `out`, returning the number of bytes written
    /// (`input.len() + 8`), or `0` if `out` is too small.
    pub fn obfuscate(&self, input: &[u8], out: &mut [u8]) -> usize {
        let out_len = input.len() + SALT_LEN;
        if out.len() < out_len {
            return 0;
        }
        rand::rng().fill_bytes(&mut out[..SALT_LEN]);
        let key = self.key(&out[..SALT_LEN]);
        for (i, &c) in input.iter().enumerate() {
            out[i + SALT_LEN] = c ^ key[i % KEY_LEN];
        }
        out_len
    }

    /// Deobfuscate `input` into `out`, returning the number of payload bytes
    /// (`input.len() - 8`), or `0` if the packet is too short / `out` too small.
    pub fn deobfuscate(&self, input: &[u8], out: &mut [u8]) -> usize {
        if input.len() <= SALT_LEN {
            return 0;
        }
        let out_len = input.len() - SALT_LEN;
        if out.len() < out_len {
            return 0;
        }
        let key = self.key(&input[..SALT_LEN]);
        for (i, &c) in input[SALT_LEN..].iter().enumerate() {
            out[i] = c ^ key[i % KEY_LEN];
        }
        out_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let s = Salamander::new(b"my-secret-key").unwrap();
        let plain = b"the quick brown fox jumps over the lazy dog";
        let mut obf = vec![0u8; plain.len() + 8];
        let n = s.obfuscate(plain, &mut obf);
        assert_eq!(n, plain.len() + 8);
        // Ciphertext differs from plaintext (salt + XOR).
        assert_ne!(&obf[8..], &plain[..]);

        let mut out = vec![0u8; plain.len()];
        let m = s.deobfuscate(&obf[..n], &mut out);
        assert_eq!(m, plain.len());
        assert_eq!(&out[..m], plain);
    }

    #[test]
    fn rejects_short_psk() {
        assert!(Salamander::new(b"abc").is_none());
        assert!(Salamander::new(b"abcd").is_some());
    }

    #[test]
    fn deobfuscate_rejects_runt() {
        let s = Salamander::new(b"key1").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(s.deobfuscate(&[0u8; 8], &mut out), 0);
        assert_eq!(s.deobfuscate(&[], &mut out), 0);
    }
}
