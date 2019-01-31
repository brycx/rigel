// MIT License

// Copyright (c) 2018-2019 brycx

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

#![feature(test)]

extern crate hmac;
extern crate orion;
extern crate rigel;
extern crate ring;
extern crate sha2;
extern crate test;

use hmac::{Hmac, Mac};
use rigel::{hmac_sha512, init};
use ring::{digest, hmac as ring_hmac};
use sha2::Sha512;
use test::Bencher;

#[bench]
fn rigel_one_shot(b: &mut Bencher) {
    let key = [0x61; 64];
    let message = "what do ya want for nothing?".as_bytes();

    b.iter(|| {
        hmac_sha512(&key, &message);
    });
}

#[bench]
fn rigel_stream(b: &mut Bencher) {
    let key = [0x61; 64];
    let message = "what do ya want for nothing?".as_bytes();

    b.iter(|| {
        let mut hmac = init(&key);
        hmac.update(&message);
        hmac.finalize();
    });
}

#[bench]
fn RustCrypto(b: &mut Bencher) {
    let key = [0x61; 64];
    let message = "what do ya want for nothing?".as_bytes();

    type HmacSha512 = Hmac<Sha512>;

    b.iter(|| {
        let mut mac = HmacSha512::new_varkey(&key).expect("HMAC can take key of any size");
        mac.input(message);
        mac.result();
    });
}

#[bench]
fn orion(b: &mut Bencher) {
    let key = [0x61; 64];
    let message = "what do ya want for nothing?".as_bytes();

    b.iter(|| {
        let mut mac = orion::hazardous::mac::hmac::init(
            &orion::hazardous::mac::hmac::SecretKey::from_slice(&key).unwrap(),
        );
        mac.update(message).unwrap();
        mac.finalize().unwrap();
    });
}

#[bench]
fn ring(b: &mut Bencher) {
    let key = [0x61; 64];
    let message = "what do ya want for nothing?".as_bytes();

    b.iter(|| {
        let key_value = ring_hmac::SigningKey::new(&digest::SHA512, &key);
        let signature = ring_hmac::sign(&key_value, message);
    });
}
