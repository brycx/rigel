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
        _ => panic!("ERROR")
    }
}

/// Struct for using HMAC with streaming messages.
pub struct HmacSha512 {
    buffer: [u8; 128],
    hasher: Sha512
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
    /// This can be called multiple times for streaming messages.
    pub fn update(&mut self, message: &[u8]) {
        self.hasher.input(message);
    }
    /// Retrieve MAC.
    pub fn finalize(&mut self) -> [u8; 64] {

        let mut hash_ires = Sha512::default();
        core::mem::swap(&mut self.hasher, &mut hash_ires);

        for idx in self.buffer.iter_mut() {
            // XOR with the result of XOR(0x36 ^ 0x5C)
            // Which is equivalent of inverting the ipad
            // and then constructing the opad
            *idx ^= 0x6A;
        }

        let mut hash_ores = Sha512::default();
        hash_ores.input(&self.buffer);
        hash_ores.input(&hash_ires.result());

        let mut mac: [u8; 64] = [0u8; 64];
        mac.copy_from_slice(&hash_ores.result());

        mac
    }
    /// Verify a MAC.
    pub fn verify(&mut self, expected_hmac: &[u8], secret_key: &[u8], message: &[u8]) -> bool {

        let mut mac = init(secret_key);
        mac.update(message);

        match mac.finalize().ct_eq(expected_hmac).unwrap_u8() {
            0 => false,
            1 => true,
            _ => panic!("ERROR")
        }
    }
}

/// Initialize HmacSha512 struct with a given key, for use with streaming messages.
pub fn init(secret_key: &[u8]) -> HmacSha512 {

    let mut mac = HmacSha512 {
        // Initialize to 128 * (0x00 ^ 0x36) so that
        // we can later xor the rest of the key in-place
        buffer: [0x36; 128],
        hasher: sha2::Sha512::default()
    };

    mac.pad_key_to_ipad(secret_key);

    mac
}
