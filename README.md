
### About
`rigel` is a minimal implementation of HMAC with SHA512, which is optimized for use
with embedded devices. `rigel` minimizes the amount of allocations made, while
still upholding performance speed.

### Security
This library has at no point received any formal cryptographic/security audit. It
should be used at own risk.

### Example

__Generate and verify a MAC__:
```rust
extern crate rigel;

let mac = rigel::hmac_sha512("Secret key".as_bytes(), "Message".as_bytes());

assert!(rigel::verify(&mac, "Secret key".as_bytes(), "Message".as_bytes()));

```

### Performance
```rust
test RustCrypto ... bench: 2,735 ns/iter (+/- 145)
test orion      ... bench: 2,531 ns/iter (+/- 148)
test rigel      ... bench: 2,108 ns/iter (+/- 76)
test ring       ... bench: 3,379 ns/iter (+/- 228)
```
This was benchmarked on a MacBook Air 1,6 GHz Intel Core i5, 4GB.

### License
`rigel` is licensed under the MIT license. See the `LICENSE` file for more information.
