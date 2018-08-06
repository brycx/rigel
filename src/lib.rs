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
fn pad_key_to_ipad(key: &[u8]) -> [u8; 192] {

    // Initialize to 192 * (0x00 ^ 0x36) so that
    // we can later xor the rest of the key in-place
    let mut padded_key = [0x36; 192];

    if key.len() > 128 {
        let hash = sha2::Sha512::digest(&key);

        for idx in 0..hash.len() {
            padded_key[idx] ^= hash[idx];
        }
    } else {
        for idx in 0..key.len() {
            padded_key[idx] ^= key[idx];
        }
    }

    padded_key
}

#[inline(always)]
/// Return HMAC-SHA512 MAC.
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {

    let mut hash_ipad = Sha512::default();
    let mut buffer: [u8; 192] = pad_key_to_ipad(key);
    // First 128 bytes is the ipad
    hash_ipad.input(&buffer[..128]);
    hash_ipad.input(message);
    buffer[128..].copy_from_slice(&hash_ipad.result());

    // Make first 128 bytes the opad
    for idx in buffer.iter_mut().take(128) {
        // XOR with the result of XOR(0x36 ^ 0x5C)
        // Which is equivalent of inverting the ipad
        // and then constructing the opad
        *idx ^= 0x6A;
    }

    let mut mac: [u8; 64] = [0u8; 64];
    mac.copy_from_slice(&sha2::Sha512::digest(&buffer));

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
