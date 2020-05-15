# easy-hasher

##### Easy hashing library for Rust

Hashing functions (example with SHA256):
- Raw binary data hash: ```sha256(&input)```
- String hash: ```string_sha256(&input)```

<br/>
Supported hashing algorithms: 

* CRC
  - CRC-8
  - CRC-16
  - CRC-32
  - CRC-64
* MD5
* SHA1
* SHA2
  - SHA-224
  - SHA-256
  - SHA-384
  - SHA-512
* SHA3 
  - SHA3-224
  - SHA3-256
  - SHA3-384
  - SHA3-512

File hashing support is coming soon too.

String SHA256 hash example:

```rust 
extern crate easy_hasher;
use easy_hasher::easy_hasher::*;

fn main() {
    let string = "example string".to_string();
    let hash = string_sha256(&string);
    let string_hash = hash.to_hex_string();

    assert_eq!(string_hash,
               "aedfb92b3053a21a114f4f301a02a3c6ad5dff504d124dc2cee6117623eec706");
    println!("sha256({}) = {}", string, string_hash);
}
```
