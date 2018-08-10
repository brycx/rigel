### rigel ![Build Status](https://travis-ci.org/brycx/rigel.svg?branch=master) [![codecov](https://codecov.io/gh/brycx/rigel/branch/master/graph/badge.svg)](https://codecov.io/gh/brycx/rigel)


### About
`rigel` is a minimal implementation of HMAC with SHA512, which is optimized for use
with embedded devices. `rigel` minimizes the amount of allocations made, while
still upholding performance speed.

You can read more about these optimizations [here](https://brycx.github.io/2018/08/06/hmac-and-precomputation-optimization.html).

### Security
This library has at no point received any formal cryptographic/security audit. It
should be used at own risk.

### Example

***With the one-shot API:***
```rust
extern crate rigel;

let mac = rigel::hmac_sha512("Secret key".as_bytes(), "Message".as_bytes());

assert!(rigel::verify(&mac, "Secret key".as_bytes(), "Message".as_bytes()));

```

***With streaming messages:***
```rust
extern crate rigel;

let mut mac = rigel::init("Secret key".as_bytes());
mac.update("Message".as_bytes());
let res = mac.finalize();
assert!(mac.verify(&res, "Secret key".as_bytes(), "Message".as_bytes()));

```

### Performance
```rust
test RustCrypto     ... bench:       2,727 ns/iter (+/- 91)
test orion          ... bench:       2,461 ns/iter (+/- 158)
test rigel_one_shot ... bench:       2,093 ns/iter (+/- 42)
test rigel_stream   ... bench:       2,161 ns/iter (+/- 58)
test ring           ... bench:       3,357 ns/iter (+/- 96)
```
This was benchmarked on a MacBook Air 1,6 GHz Intel Core i5, 4GB.

### License
`rigel` is licensed under the MIT license. See the `LICENSE` file for more information.
