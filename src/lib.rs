/// Easy Hasher module
pub mod easy_hasher {
    type _Byte = u8;
    type _Data = Vec<_Byte>;
    type _Input<'a> = &'a String;
    use sha3::Digest;
    use sha1::Sha1;
    use std::borrow::Borrow;

    mod filedata {
        use std::fs;
        use std::io::Read;
        use crate::easy_hasher::_Data;

        pub(crate) struct FileData {
            fp: fs::File,
            fm: fs::Metadata,
        }

        impl FileData {
            pub fn open<P: AsRef<std::path::Path>>(p: P) -> Result<FileData, String> {
                let _fp = fs::File::open(p);
                let _file: fs::File;
                match _fp {
                    Ok(f) => _file = f,
                    Err(e) => return Err(e.to_string())
                };

                let _fm = _file.metadata();
                let _meta: fs::Metadata;
                match _fm {
                    Ok(m) => _meta = m,
                    Err(e) => return Err(e.to_string())
                }

                Ok(
                    FileData {
                        fp: _file,
                        fm: _meta,
                    }
                )
            }

            pub fn to_vec(mut self) -> Result<_Data, String> {
                let mut vec = vec![0; self.fm.len() as usize];
                let _res = self.fp.read(&mut vec);
                match _res {
                    Ok(r) => if vec.len() == r {
                        Ok(vec)
                    } else {
                        Err("error reading from file".to_string())
                    },
                    Err(e) => Err(e.to_string()),
                }
            }

            #[allow(dead_code)]
            pub fn file(self) -> fs::File {
                self.fp
            }

            #[allow(dead_code)]
            pub fn metadata(self) -> fs::Metadata {
                self.fm
            }
        }
    }

    pub struct Hash {
        hash: _Data,
        length: usize
    }

    impl Hash {
        /// Performs the conversion from `Vec<u8>` to `String`
        pub fn hex_string(data: &_Data) -> String {
            data
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect()
        }

        pub fn from_vec(data: &_Data) -> Hash {
            Hash {
                hash: data.clone(),
                length: data.len()
            }
        }

        /// Express hash as hex string
        pub fn to_hex_string(&self) -> String {
            Hash::hex_string(&self.hash)
        }

        /// Get hash as `Vec<u8>`
        pub fn to_vec(&self) -> _Data {
            self.hash.clone()
        }

        pub fn len(&self) -> usize {
            self.length
        }
    }

    /// Generic hashing function
    fn sha3<T>(mut hasher: T, data: _Data) -> Hash where T: Digest {
        hasher.input(data.as_slice());
        let result = hasher
            .result()
            .to_vec();
        Hash::from_vec(&result)
    }

    fn sha(data: _Data) -> Hash {
        let mut hasher = Sha1::new();
        hasher.update(data.as_slice());
        let result = hasher
            .digest()
            .bytes()
            .to_vec();
        Hash::from_vec(&result)
    }

    fn md2n<T>(mut hasher: T, data: _Data) -> Hash where T: Digest {
        hasher.input(data.as_slice());
        let result = hasher
            .result()
            .to_vec();
        Hash::from_vec(&result)
    }

    /// CRC8 raw data hashing function, based on polynomial and initial value
    pub fn param_crc8(data: _Data, poly: u8, init: u8) -> Hash {
        let mut crc8 = crc8::Crc8::create_msb(poly);
        let result = vec![crc8.calc(data.as_slice(), data.len() as i32, init)];
        Hash::from_vec(&result)
    }

    /// Generic-algorithm file hasher
    pub fn file_hash(hasher: fn(_Data) -> Hash, filename: _Input) -> Result<Hash, String> {
        use filedata::*;
        let rfd = FileData::open(filename);
        let fd: FileData;

        match rfd {
            Ok(data) => {
                fd = data
            },
            Err(e) => {
                println!("{}", e);
                return Err(e)
            },
        }

        let rcont = fd.to_vec();
        let cont: _Data;

        match rcont {
            Ok(bytes) => cont = bytes,
            Err(e) => return Err(e),
        }

        Ok(hasher(cont))
    }

    /* file hashing */

    /// CRC8 file hashing function\
    /// poly = 0x07, init = 0x00
    pub fn file_crc8(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_crc8, filename)
    }

    /// CRC16/ARC file hashing function
    pub fn file_crc16(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_crc16, filename)
    }

    /// CRC32/IEEE file hashing function
    pub fn file_crc32(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_crc32, filename)
    }

    /// CRC64/ECMA file hashing function
    pub fn file_crc64(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_crc64, filename)
    }

    /// MD5 file hashing function
    pub fn file_md5(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_md5, filename)
    }

    /// SHA-1 file hashing function
    pub fn file_sha1(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_sha1, filename)
    }

    /// SHA-224 file hashing function
    pub fn file_sha224(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_sha224, filename)
    }

    /// SHA-256 file hashing function
    pub fn file_sha256(filename: String) -> Result<Hash, String> {
        file_hash(raw_sha256, filename.borrow())
    }

    /// SHA-384 file hashing function
    pub fn file_sha384(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_sha384, filename)
    }

    /// SHA-512 file hashing function
    pub fn file_sha512(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_sha512, filename)
    }

    /// SHA3-224 file hashing function
    pub fn file_sha3_224(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_sha3_224, filename)
    }

    /// SHA3-256 file hashing function
    pub fn file_sha3_256(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_sha3_256, filename)
    }

    /// SHA3-384 file hashing function
    pub fn file_sha3_384(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_sha3_384, filename)
    }

    /// SHA3-512 file hashing function
    pub fn file_sha3_512(filename: _Input) -> Result<Hash, String> {
        file_hash(raw_sha3_512, filename)
    }

    /* Raw data hashing functions */

    /// CRC8 raw data hashing function\
    /// poly = 0x07, init = 0x00
    pub fn raw_crc8(d: _Data) -> Hash {
        param_crc8(d, 0x7, 0x0)
    }

    /// CRC16/ARC raw data hashing function
    pub fn raw_crc16(d: _Data) -> Hash {
        let result = crc16::State::<crc16::ARC>::calculate(d.as_slice())
            .to_be_bytes()
            .to_vec()
            .clone();
        Hash::from_vec(&result)
    }

    /// CRC32 raw data hashing function
    pub fn raw_crc32(d: _Data) -> Hash {
        let result = crc::crc32::checksum_ieee(d.as_slice())
            .to_be_bytes()
            .to_vec()
            .clone();
        Hash::from_vec(&result)
    }

    /// CRC64 raw data hashing function
    pub fn raw_crc64(d: _Data) -> Hash {
        let result = crc::crc64::checksum_ecma(d.as_slice())
            .to_be_bytes()
            .to_vec()
            .clone();
        Hash::from_vec(&result)
    }

    /// MD2 raw data hashing function
    pub fn raw_md2(d: _Data) -> Hash {
        use md2::Md2;
        md2n(Md2::new(), d)
    }

    /// MD4 raw data hashing function
    pub fn raw_md4(d: _Data) -> Hash {
        use md4::Md4;
        md2n(Md4::new(), d)
    }

    /// MD5 raw data hashing function
    pub fn raw_md5(d: _Data) -> Hash {
        let result = md5::compute(d)
            .0
            .to_vec();
        Hash::from_vec(&result)
    }

    /// SHA-1 raw data hashing function
    pub fn raw_sha1(d: _Data) -> Hash {
        sha(d)
    }

    /// SHA-224 raw data hashing function
    pub fn raw_sha224(d: _Data) -> Hash {
        sha3(sha2::Sha224::new(), d)
    }

    /// SHA-256 raw data hashing function
    pub fn raw_sha256(d: _Data) -> Hash {
        sha3(sha2::Sha256::new(), d)
    }

    /// SHA-384 raw data hashing function
    pub fn raw_sha384(d: _Data) -> Hash {
        sha3(sha2::Sha384::new(), d)
    }

    /// SHA-512 raw data hashing function
    pub fn raw_sha512(d: _Data) -> Hash {
        sha3(sha2::Sha512::new(), d)
    }

    /// SHA3-224 raw data hashing function
    pub fn raw_sha3_224(d: _Data) -> Hash {
        sha3(sha3::Sha3_224::new(), d)
    }

    /// SHA3-256 raw data hashing function
    pub fn raw_sha3_256(d: _Data) -> Hash {
        sha3(sha3::Sha3_256::new(), d)
    }

    /// SHA3-384 raw data hashing function
    pub fn raw_sha3_384(d: _Data) -> Hash {
        sha3(sha3::Sha3_384::new(), d)
    }

    /// SHA3-512 raw data hashing function
    pub fn raw_sha3_512(d: _Data) -> Hash {
        sha3(sha3::Sha3_512::new(), d)
    }

    /* String hashing functions */

    /// CRC8 string hashing function\
    /// poly = 0x07, init = 0x00
    pub fn crc8(s: _Input) -> Hash {
        raw_crc8(s.clone().into_bytes())
    }

    /// CRC16/ARC string hashing function
    pub fn crc16(s: _Input) -> Hash {
        raw_crc16(s.clone().into_bytes())
    }

    /// CRC32 string hashing function
    pub fn crc32(s: _Input) -> Hash {
        raw_crc32(s.clone().into_bytes())
    }

    /// CRC64 string hashing function
    pub fn crc64(s: _Input) -> Hash {
        raw_crc64(s.clone().into_bytes())
    }

    /// MD5 string hashing function
    pub fn md2(s: _Input) -> Hash {
        raw_md2(s.clone().into_bytes())
    }

    /// MD5 string hashing function
    pub fn md4(s: _Input) -> Hash {
        raw_md4(s.clone().into_bytes())
    }

    /// MD5 string hashing function
    pub fn md5(s: _Input) -> Hash {
        raw_md5(s.clone().into_bytes())
    }

    /// SHA-1 string hashing function
    pub fn sha1(s: _Input) -> Hash {
        raw_sha1(s.clone().into_bytes())
    }

    /// SHA-224 string hashing function
    pub fn sha224(s: _Input) -> Hash {
        raw_sha224(s.clone().into_bytes())
    }

    /// SHA-256 string hashing function
    pub fn sha256(s: _Input) -> Hash {
        raw_sha256(s.clone().into_bytes())
    }

    /// SHA-384 string hashing function
    pub fn sha384(s: _Input) -> Hash {
        raw_sha384(s.clone().into_bytes())
    }

    /// SHA-512 string hashing function
    pub fn sha512(s: _Input) -> Hash {
        raw_sha512(s.clone().into_bytes())
    }

    /// SHA3-224 string hashing function
    pub fn sha3_224(s: _Input) -> Hash {
        raw_sha3_224(s.clone().into_bytes())
    }

    /// SHA3-256 string hashing function
    pub fn sha3_256(s: _Input) -> Hash {
        raw_sha3_256(s.clone().into_bytes())
    }

    /// SHA3-384 string hashing function
    pub fn sha3_384(s: _Input) -> Hash {
        raw_sha3_384(s.clone().into_bytes())
    }

    /// SHA3-512 string hashing function
    pub fn sha3_512(s: _Input) -> Hash {
        raw_sha3_512(s.clone().into_bytes())
    }
}