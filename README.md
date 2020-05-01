# easy-hasher

##### Easy hashing library for Rust

Hashing functions (example with SHA256):
- Raw binary data hash: ```sha256(input)```
- String hash: ```string_sha256(input)```

<br/>
Supported hashing algorithms: 
- MD5
- SHA1
- SHA2
  - SHA224
  - SHA256
  - SHA384
  - SHA512
- SHA3 _(coming soon)_
- CRC16 _(coming soon)_
- CRC32 _(coming soon)_

File hashing support is coming soon too.

String SHA256 hash example:

```rust 
extern crate easy_hasher;
use easy_hasher::easy_hasher::*;

fn main() {
	let string = "example string".to_string();
	let hash = string_sha256(string.clone());

	println!("sha256({}) = {}", string, hex_string(hash));
}
```
