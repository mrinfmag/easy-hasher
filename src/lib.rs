/// Easy Hasher module
pub mod easy_hasher {
    type _Byte = u8;
    type _Data = Vec<_Byte>;
    use sha2::Digest;
    use sha1::Sha1;

    /// Performs the conversion from `u8` slice to `String`
    pub fn hex_string(data: _Data) -> String {
        data
            .iter()
            .map(|byte| format!("{:x}", byte))
            .collect()
    }

    /// Generic hashing function
    fn sha2<T>(mut hasher: T, data: _Data) -> _Data where T: Digest {
        hasher.input(data.as_slice());
        hasher
            .result()
            .to_vec()
    }

    fn sha(data: _Data) -> _Data {
        let mut hasher = Sha1::new();
        hasher.update(data.as_slice());
        hasher.digest().bytes().to_vec()
    }

    /* Raw data hashing functions */

    /// SHA-1 raw data hashing function
    pub fn sha1(d: _Data) -> _Data {
        sha(d)
    }

    /// SHA-224 raw data hashing function
    pub fn sha224(d: _Data) -> _Data {
        sha2(sha2::Sha224::new(), d)
    }

    /// SHA-256 raw data hashing function
    pub fn sha256(d: _Data) -> _Data {
        sha2(sha2::Sha256::new(), d)
    }

    /// SHA-384 raw data hashing function
    pub fn sha384(d: _Data) -> _Data {
        sha2(sha2::Sha384::new(), d)
    }

    /// SHA-512 raw data hashing function
    pub fn sha512(d: _Data) -> _Data {
        sha2(sha2::Sha512::new(), d)
    }

    /* String hashing functions */

    pub fn string_sha1(s: String) -> _Data {
        sha1(s.as_bytes().to_vec())
    }

    /// SHA-224 string hashing function
    pub fn string_sha224(s: String) -> _Data {
        sha224(s.as_bytes().to_vec())
    }

    /// SHA-256 string hashing function
    pub fn string_sha256(s: String) -> _Data {
        sha256(s.as_bytes().to_vec())
    }

    /// SHA-384 string hashing function
    pub fn string_sha384(s: String) -> _Data {
        sha384(s.as_bytes().to_vec())
    }

    /// SHA-512 string hashing function
    pub fn string_sha512(s: String) -> _Data {
        sha512(s.as_bytes().to_vec())
    }
}