// MIT License

// Copyright (c) 2018 brycx

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#![no_std]
#[cfg(test)]
pub mod tests;
extern crate sha2;
extern crate subtle;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

/// Pad key and construct inner-padding
fn pad_key_to_ipad(key: &[u8]) -> [u8; 128] {
    // Initialize to 128 * (0x00 ^ 0x36) so that
    // we can later xor the rest of the key in-place
    let mut padded_key = [0x36; 128];

    if key.len() > 128 {
        padded_key[..64].copy_from_slice(&sha2::Sha512::digest(&key));

        for itm in padded_key.iter_mut().take(64) {
            *itm ^= 0x36;
        }
    } else {
        for idx in 0..key.len() {
            padded_key[idx] ^= key[idx];
        }
    }

    padded_key
}

#[inline(always)]
/// HMAC-SHA512 one-shot function. Returns a MAC.
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut hash_ires = Sha512::default();
    let mut buffer = pad_key_to_ipad(key);
    hash_ires.input(&buffer);
    hash_ires.input(message);

    for idx in buffer.iter_mut() {
        // XOR with the result of XOR(0x36 ^ 0x5C)
        // Which is equivalent of inverting the ipad
        // and then constructing the opad
        *idx ^= 0x6A;
    }

    let mut hash_ores = Sha512::default();
    hash_ores.input(&buffer);
    hash_ores.input(&hash_ires.result());

    let mut mac: [u8; 64] = [0u8; 64];
    mac.copy_from_slice(&hash_ores.result());

    mac
}

/// Verify a HMAC-SHA512 MAC.
pub fn verify(expected_hmac: &[u8], key: &[u8], message: &[u8]) -> bool {
    let mac = hmac_sha512(key, message);

    match mac.ct_eq(expected_hmac).unwrap_u8() {
        0 => false,
        1 => true,
        _ => panic!("ERROR"),
    }
}

/// Struct for using HMAC with streaming messages.
pub struct HmacSha512 {
    buffer: [u8; 128],
    hasher: Sha512,
    is_finalized: bool,
}

impl HmacSha512 {
    /// Pad key and construct inner-padding
    fn pad_key_to_ipad(&mut self, key: &[u8]) {
        if key.len() > 128 {
            self.buffer[..64].copy_from_slice(&sha2::Sha512::digest(&key));

            for itm in self.buffer.iter_mut().take(64) {
                *itm ^= 0x36;
            }
        } else {
            for idx in 0..key.len() {
                self.buffer[idx] ^= key[idx];
            }
        }

        self.hasher.input(&self.buffer);
    }
    /// Call the core finalization steps.
    fn core_finalize(&mut self, hash_ores: &mut Sha512) {
        if self.is_finalized {
            panic!("Unable to call finalize twice without reset");
        }

        self.is_finalized = true;

        let mut hash_ires = Sha512::default();
        core::mem::swap(&mut self.hasher, &mut hash_ires);

        for idx in self.buffer.iter_mut() {
            // XOR with the result of XOR(0x36 ^ 0x5C)
            // Which is equivalent of inverting the ipad
            // and then constructing the opad
            *idx ^= 0x6A;
        }

        hash_ores.input(&self.buffer);
        hash_ores.input(&hash_ires.result());
    }

    /// Reset to 'init()' state.
    pub fn reset(&mut self) {
        if self.is_finalized {
            for idx in self.buffer.iter_mut() {
                // XOR with the result of XOR(0x36 ^ 0x5C)
                // Which is equivalent of inverting the opad
                // and then constructing the ipad
                *idx ^= 0x6A;
            }
            self.hasher.input(&self.buffer);
            self.is_finalized = false;
        } else {
            panic!("No need to reset");
        }
    }
    /// This can be called multiple times for streaming messages.
    pub fn update(&mut self, message: &[u8]) {
        self.hasher.input(message);
    }
    /// Retrieve MAC.
    pub fn finalize(&mut self) -> [u8; 64] {
        let mut hash_ores = Sha512::default();
        self.core_finalize(&mut hash_ores);

        let mut mac: [u8; 64] = [0u8; 64];
        mac.copy_from_slice(&hash_ores.result());

        mac
    }
    /// Retrieve MAC and copy into `dst`.
    pub fn finalize_with_dst(&mut self, dst: &mut [u8]) {
        let mut hash_ores = Sha512::default();
        self.core_finalize(&mut hash_ores);
        let dst_len = dst.len();

        dst.copy_from_slice(&hash_ores.result()[..dst_len]);
    }
    /// Verify a MAC.
    pub fn verify(&mut self, expected_hmac: &[u8], secret_key: &[u8], message: &[u8]) -> bool {
        let mut mac = init(secret_key);
        mac.update(message);

        match mac.finalize().ct_eq(expected_hmac).unwrap_u8() {
            0 => false,
            1 => true,
            _ => panic!("ERROR"),
        }
    }
}

/// Initialize HmacSha512 struct with a given key, for use with streaming messages.
pub fn init(secret_key: &[u8]) -> HmacSha512 {
    let mut mac = HmacSha512 {
        // Initialize to 128 * (0x00 ^ 0x36) so that
        // we can later xor the rest of the key in-place
        buffer: [0x36; 128],
        hasher: sha2::Sha512::default(),
        is_finalized: false,
    };

    mac.pad_key_to_ipad(secret_key);

    mac
}

#[test]
#[should_panic]
fn finalize_no_reset_panic() {
    let mut out = [0u8; 64];
    let mut mac = init("secret key".as_bytes());
    mac.update("msg".as_bytes());
    mac.finalize_with_dst(&mut out);
    mac.finalize_with_dst(&mut out);
}

#[test]
#[should_panic]
fn finalize_no_reset_panic_2() {
    let mut mac = init("secret key".as_bytes());
    mac.update("msg".as_bytes());
    mac.finalize();
    mac.finalize();
}

#[test]
#[should_panic]
fn finalize_no_reset_panic_3() {
    let mut out = [0u8; 64];
    let mut mac = init("secret key".as_bytes());
    mac.update("msg".as_bytes());
    mac.finalize();
    mac.finalize_with_dst(&mut out);
}

#[test]
#[should_panic]
fn double_reset() {
    let mut mac = init("secret key".as_bytes());
    mac.update("msg".as_bytes());
    mac.finalize();
    mac.reset();
    mac.reset();
}

#[test]
fn hmac_verify() {
    let mut out = [0u8; 64];
    let mut mac = init("secret key".as_bytes());
    mac.update("msg".as_bytes());
    mac.finalize_with_dst(&mut out);

    let mac_oneshot = hmac_sha512("secret key".as_bytes(), "msg".as_bytes());

    assert!(mac.verify(&out, "secret key".as_bytes(), "msg".as_bytes()));
    assert!(mac.verify(&mac_oneshot, "secret key".as_bytes(), "msg".as_bytes()));
    assert!(verify(&out, "secret key".as_bytes(), "msg".as_bytes()));
    assert!(verify(
        &mac_oneshot,
        "secret key".as_bytes(),
        "msg".as_bytes()
    ));
}

#[test]
fn hmac_verify_after_reset() {
    let mut out = [0u8; 64];
    let mut mac = init("secret key".as_bytes());
    mac.update("msg".as_bytes());
    mac.finalize_with_dst(&mut out);
    mac.reset();
    mac.update("msg".as_bytes());

    assert_eq!(out.as_ref(), mac.finalize().as_ref());
}
