# easy-hasher

### Easy hashing library for Rust

Hashing functions (all examples using SHA256):
- String: ```sha256(&input)```<sup>1</sup>
- File: ```file_sha256(&input)```<sup>1</sup>
- Raw binary data: ```raw_sha256(input.clone())```<sup>2</sup>

<br/>
Supported algorithms: 

* CRC
  - CRC-8
  - CRC-16
  - CRC-32
  - CRC-64
* MD2
* MD4
* MD5
* SHA1
* SHA2
  - SHA-224
  - SHA-256
  - SHA-384
  - SHA-512
  - SHA-512/224
  - SHA-512/256
* SHA3 
  - SHA3-224
  - SHA3-256
  - SHA3-384
  - SHA3-512
* SHA3 
  - Keccak224
  - Keccak256
  - Keccak384
  - Keccak512
  
SHAKE128 and SHAKE256 are coming soon!

#### Code examples:
String hash:

```rust 
extern crate easy_hasher;
use easy_hasher::easy_hasher::*;

fn main() {
    let string = "example string".to_string();
    let hash = sha256(&string);
    let string_hash = hash.to_hex_string();

    assert_eq!(string_hash,
               "aedfb92b3053a21a114f4f301a02a3c6ad5dff504d124dc2cee6117623eec706");
    println!("SHA256({}) = {}", string, string_hash);
}
```
\
Raw data hash:

```rust 
extern crate easy_hasher;
use easy_hasher::easy_hasher::*;

fn main() {
    let data = vec![0xA7, 0x34, 0x9F, 0x02]; // just random data lol
    let hash = raw_sha256(data.clone());
    let string_hash = hash.to_hex_string();

    assert_eq!(string_hash,
        "54dd1903dd45589e9f30e5cb4529d09417347cb27c2f478c7a9e33875917000c");
    println!("SHA256({}) = {}", Hash::hex_string(&data), string_hash);
}
```
\
File hash:

```rust
extern crate easy_hasher;
use easy_hasher::easy_hasher::*;

fn main() {
    let path = get_input(); //some input function
    let file256 = file_sha256(&path);
    let hash: Hash;

    match file256 {
        Ok(h) => hash = h,
        Err(..) => abort()
    }
    println!("SHA256({}) = {}", path, hash.to_hex_string());
}
```

<br/>
<sup>1</sup>: Passing by reference to avoid E0382 (borrow of moved value) <br/>
<sup>2</sup>: Using .clone() function for the same reason (and to simplify code)