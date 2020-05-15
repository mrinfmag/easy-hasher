/// Easy Hasher module
pub mod easy_hasher {
    type _Byte = u8;
    type _Data = Vec<_Byte>;
    type _Input<'a> = &'a String;


    pub struct Hash {
        hash: _Data
    }

    impl Hash {
        /// Performs the conversion from `Vec<u8>` to `String`
        pub fn hex_string(data: &_Data) -> String {
            data
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect()
        }

        /// Express hash as hex string
        pub fn to_hex_string(&self) -> String {
            Hash::hex_string(&self.hash)
        }

        /// Get hash as `Vec<u8>`
        pub fn to_vec(&self) -> _Data {
            self.hash.clone()
        }
    }

    use sha3::Digest;
    use sha1::Sha1;

    /// Performs the conversion from `Vec<u8>` to `String`
    pub fn hex_string(data: _Data) -> String {
        data
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }

    /// Generic SHA2/SHA3 hashing function
    fn sha3<T>(mut hasher: T, data: _Data) -> Hash where T: Digest {
        hasher.input(data.as_slice());
        Hash {
            hash: hasher
                .result()
                .to_vec()
        }
    }

    fn sha(data: _Data) -> Hash {
        let mut hasher = Sha1::new();
        hasher.update(data.as_slice());
        Hash {
            hash: hasher.digest().bytes().to_vec()
        }
    }
    /// CRC8 raw data hashing function, based on polynomial and initial value
    pub fn param_crc8(data: _Data, poly: u8, init: u8) -> Hash {
        let mut crc8 = crc8::Crc8::create_msb(poly);
        Hash {
            hash: vec![crc8.calc(data.as_slice(), data.len() as i32, init)]
        }
    }

    /* Raw data hashing functions */

    // CRC

    /// CRC8 raw data hashing function\
    /// poly = 0x07, init = 0x00
    pub fn crc8(d: _Data) -> Hash {
        param_crc8(d, 0x7, 0x0)
    }

    /// CRC16/ARC raw data hashing function
    pub fn crc16(d: _Data) -> Hash {
        Hash {
            hash: crc16::State::<crc16::ARC>::calculate(d.as_slice()).to_be_bytes().to_vec()
        }
    }

    /// CRC32 raw data hashing function
    pub fn crc32(d: _Data) -> Hash {
        Hash {
            hash: crc::crc32::checksum_ieee(d.as_slice()).to_be_bytes().to_vec()
        }
    }

    /// CRC64 raw data hashing function
    pub fn crc64(d: _Data) -> Hash {
        Hash {
            hash: crc::crc64::checksum_ecma(d.as_slice()).to_be_bytes().to_vec()
        }
    }

    // MD5

    /// MD5 raw data hashing function
    pub fn md5(d: _Data) -> Hash {
        Hash {
            hash: md5::compute(d).0.to_vec()
        }
    }

    // SHA1

    /// SHA1 raw data hashing function
    pub fn sha1(d: _Data) -> Hash {
        sha(d)
    }

    // SHA2

    /// SHA-224 raw data hashing function
    pub fn sha224(d: _Data) -> Hash {
        sha3(sha2::Sha224::new(), d)
    }

    /// SHA-256 raw data hashing function
    pub fn sha256(d: _Data) -> Hash {
        sha3(sha2::Sha256::new(), d)
    }

    /// SHA-384 raw data hashing function
    pub fn sha384(d: _Data) -> Hash {
        sha3(sha2::Sha384::new(), d)
    }

    /// SHA-512 raw data hashing function
    pub fn sha512(d: _Data) -> Hash {
        sha3(sha2::Sha512::new(), d)
    }

    // SHA3

    /// SHA3-224 raw data hashing function
    pub fn sha3_224(d: _Data) -> Hash {
        sha3(sha3::Sha3_224::new(), d)
    }

    /// SHA3-256 raw data hashing function
    pub fn sha3_256(d: _Data) -> Hash {
        sha3(sha3::Sha3_256::new(), d)
    }

    /// SHA3-384 raw data hashing function
    pub fn sha3_384(d: _Data) -> Hash {
        sha3(sha3::Sha3_384::new(), d)
    }

    /// SHA3-512 raw data hashing function
    pub fn sha3_512(d: _Data) -> Hash {
        sha3(sha3::Sha3_512::new(), d)
    }

    /* String hashing functions */

    // CRC

    /// CRC8 string hashing function\
    /// poly = 0x07, init = 0x00
    pub fn string_crc8(s: _Input) -> Hash {
        crc8(s.clone().into_bytes())
    }

    /// CRC16/ARC string hashing function
    pub fn string_crc16(s: _Input) -> Hash {
        crc16(s.clone().into_bytes())
    }

    /// CRC32 string hashing function
    pub fn string_crc32(s: _Input) -> Hash {
        crc32(s.clone().into_bytes())
    }

    /// CRC64 string hashing function
    pub fn string_crc64(s: _Input) -> Hash {
        crc64(s.clone().into_bytes())
    }

    // MD5

    /// MD5 string hashing function
    pub fn string_md5(s: _Input) -> Hash {
        md5(s.clone().into_bytes())
    }

    // SHA1

    /// SHA1 string hashing function
    pub fn string_sha1(s: _Input) -> Hash {
        sha1(s.clone().into_bytes())
    }

    // SHA2

    /// SHA-224 string hashing function
    pub fn string_sha224(s: _Input) -> Hash {
        sha224(s.clone().into_bytes())
    }

    /// SHA-256 string hashing function
    pub fn string_sha256(s: _Input) -> Hash {
        sha256(s.clone().into_bytes())
    }

    /// SHA-384 string hashing function
    pub fn string_sha384(s: _Input) -> Hash {
        sha384(s.clone().into_bytes())
    }

    /// SHA-512 string hashing function
    pub fn string_sha512(s: _Input) -> Hash {
        sha512(s.clone().into_bytes())
    }

    // SHA3

    /// SHA3-224 string hashing function
    pub fn string_sha3_224(s: _Input) -> Hash {
        sha3_224(s.clone().into_bytes())
    }

    /// SHA3-256 string hashing function
    pub fn string_sha3_256(s: _Input) -> Hash {
        sha3_256(s.clone().into_bytes())
    }

    /// SHA3-384 string hashing function
    pub fn string_sha3_384(s: _Input) -> Hash {
        sha3_384(s.clone().into_bytes())
    }

    /// SHA3-512 string hashing function
    pub fn string_sha3_512(s: _Input) -> Hash {
        sha3_512(s.clone().into_bytes())
    }
}