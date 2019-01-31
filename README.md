# rigel
![Build Status](https://travis-ci.org/brycx/rigel.svg?branch=master) [![codecov](https://codecov.io/gh/brycx/rigel/branch/master/graph/badge.svg)](https://codecov.io/gh/brycx/rigel)


### About
`rigel` is a minimal implementation of HMAC with SHA512, which is optimized for use
with embedded devices. `rigel` minimizes the amount of allocations made, while
still upholding performance speed.

You can read more about these optimizations [here](https://brycx.github.io/2018/08/06/hmac-and-precomputation-optimization.html).


### Rust nightly
`rigel` requires Rust nightly.

### Security
This library has at no point received any formal cryptographic/security audit. It
should be **used at own risk**.

### Example

***One-shot API:***
```rust
extern crate rigel;

let mac = rigel::hmac_sha512("Secret key".as_bytes(), "Message".as_bytes());

assert!(rigel::verify(&mac, "Secret key".as_bytes(), "Message".as_bytes()));

```

***Streaming API:***
```rust
extern crate rigel;

let mut mac = rigel::init("Secret key".as_bytes());
mac.update("Message".as_bytes());
let res = mac.finalize();
assert!(mac.verify(&res, "Secret key".as_bytes(), "Message".as_bytes()));

let mut mac_out = [0u8; 64];
mac.reset();
mac.update("Other message".as_bytes());
mac.finalize_with_dst(&mut mac_out);
```

### Performance
```
test RustCrypto     ... bench:       2,039 ns/iter (+/- 14)
test orion          ... bench:       2,206 ns/iter (+/- 0)
test rigel_one_shot ... bench:       1,922 ns/iter (+/- 0)
test rigel_stream   ... bench:       1,999 ns/iter (+/- 0)
test ring           ... bench:       1,293 ns/iter (+/- 1)
```
This was benchmarked on a Intel Core i9-7960X CPU @ 2.80GHz.

### License
`rigel` is licensed under the MIT license. See the `LICENSE` file for more information.
