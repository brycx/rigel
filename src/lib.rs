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

extern crate seckey;
extern crate sha2;
extern crate subtle;
use seckey::zero;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

/// The blocksize for the hash function SHA512.
pub const SHA2_BLOCKSIZE: usize = 128;
/// The output size for the hash function SHA512.
pub const HLEN: usize = 64;
/// Type for an array of length `SHA2_BLOCKSIZE`.
pub type PadArray = [u8; SHA2_BLOCKSIZE];
/// Type for a MAC-sized array.
pub type MacArray = [u8; HLEN];

#[inline(always)]
/// Invert the buffer from opad to ipad or vice versa
fn reverse_pad(buffer: &mut PadArray) {
    for idx in buffer.iter_mut() {
        // XOR with the result of XOR(0x36 ^ 0x5C)
        // Which is equivalent of inverting the ipad
        // and then constructing the opad
        *idx ^= 0x6A;
    }
}

#[inline(always)]
/// Pad key and construct inner-padding
fn pad_key_to_ipad(key: &[u8], buffer: &mut PadArray) {
    if key.len() > SHA2_BLOCKSIZE {
        buffer[..HLEN].copy_from_slice(&sha2::Sha512::digest(&key));

        for itm in buffer.iter_mut().take(HLEN) {
            *itm ^= 0x36;
        }
    } else {
        for idx in 0..key.len() {
            buffer[idx] ^= key[idx];
        }
    }
}

#[inline(always)]
/// HMAC-SHA512 one-shot function. Returns a MAC.
pub fn hmac_sha512(key: &[u8], message: &[u8]) -> MacArray {
    let mut hash_ires = Sha512::default();
    // Initialize to 128 * (0x00 ^ 0x36) so that
    // we can later xor the rest of the key in-place
    let mut buffer = [0x36; SHA2_BLOCKSIZE];
    pad_key_to_ipad(key, &mut buffer);
    hash_ires.input(&buffer);
    hash_ires.input(message);

    reverse_pad(&mut buffer);

    let mut hash_ores = Sha512::default();
    hash_ores.input(&buffer);
    hash_ores.input(&hash_ires.result());

    let mut mac = [0u8; HLEN];
    mac.copy_from_slice(&hash_ores.result());

    zero(&mut buffer);

    mac
}

/// Verify a HMAC-SHA512 MAC in constant time.
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
    buffer: PadArray,
    hasher: Sha512,
    is_finalized: bool,
}

impl Drop for HmacSha512 {
    fn drop(&mut self) {
        zero(&mut self.buffer)
    }
}

impl HmacSha512 {
    #[inline(always)]
    /// Call the core finalization steps.
    fn core_finalize(&mut self, hash_ores: &mut Sha512) {
        if self.is_finalized {
            panic!("Unable to call finalize twice without reset");
        }

        self.is_finalized = true;

        let mut hash_ires = Sha512::default();
        core::mem::swap(&mut self.hasher, &mut hash_ires);

        reverse_pad(&mut self.buffer);

        hash_ores.input(&self.buffer);
        hash_ores.input(&hash_ires.result());
    }

    #[inline(always)]
    /// Reset to 'init()' state.
    pub fn reset(&mut self) {
        if self.is_finalized {
            reverse_pad(&mut self.buffer);
            self.hasher.input(&self.buffer);
            self.is_finalized = false;
        } else {
            ()
        }
    }

    #[inline(always)]
    /// This can be called multiple times for streaming messages.
    pub fn update(&mut self, message: &[u8]) {
        if self.is_finalized {
            panic!("Unable to call update after finalize without reset");
        }
        self.hasher.input(message);
    }

    #[inline(always)]
    /// Retrieve MAC.
    pub fn finalize(&mut self) -> MacArray {
        let mut hash_ores = Sha512::default();
        self.core_finalize(&mut hash_ores);

        let mut mac = [0u8; HLEN];
        mac.copy_from_slice(&hash_ores.result());

        mac
    }

    #[inline(always)]
    /// Retrieve MAC and copy into `dst`.
    pub fn finalize_with_dst(&mut self, dst: &mut [u8]) {
        let mut hash_ores = Sha512::default();
        self.core_finalize(&mut hash_ores);
        let dst_len = dst.len();

        dst.copy_from_slice(&hash_ores.result()[..dst_len]);
    }
}

/// Initialize HmacSha512 struct with a given key, for use with streaming messages.
pub fn init(secret_key: &[u8]) -> HmacSha512 {
    let mut mac = HmacSha512 {
        // Initialize to 128 * (0x00 ^ 0x36) so that
        // we can later xor the rest of the key in-place
        buffer: [0x36; SHA2_BLOCKSIZE],
        hasher: sha2::Sha512::default(),
        is_finalized: false,
    };

    pad_key_to_ipad(secret_key, &mut mac.buffer);
    mac.hasher.input(&mac.buffer);

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
fn update_after_finalize() {
    let mut mac = init("secret key".as_bytes());
    mac.update("msg".as_bytes());
    mac.finalize();
    mac.update("msg".as_bytes());
}

#[test]
fn hmac_verify() {
    let mut out = [0u8; 64];
    let mut mac = init("secret key".as_bytes());
    mac.update("msg".as_bytes());
    mac.finalize_with_dst(&mut out);

    let mac_oneshot = hmac_sha512("secret key".as_bytes(), "msg".as_bytes());

    assert!(verify(&out, "secret key".as_bytes(), "msg".as_bytes()));
    assert!(verify(
        &mac_oneshot,
        "secret key".as_bytes(),
        "msg".as_bytes()
    ));
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

#[test]
fn hmac_verify_after_reset_err() {
    let mut out = [0u8; 64];
    let mut mac = init("secret key".as_bytes());
    mac.update("msg".as_bytes());
    mac.finalize_with_dst(&mut out);
    mac.reset();
    mac.update("other message".as_bytes());

    assert_ne!(out.as_ref(), mac.finalize().as_ref());
}
