use crate::{Algorithm, LessPassError};

#[derive(Debug, Clone)]
pub struct Master {
    master: Vec<u8>,
    algorithm: Algorithm,
}

impl Master {
    pub fn new(master: &str, algorithm: Algorithm) -> crate::Result<Self> {
        if algorithm == Algorithm::SHA1 {
            Err(LessPassError::UnsupportedAlgorithm)
        } else {
            Ok(Self {
                master: master.as_bytes().to_vec(),
                algorithm,
            })
        }
    }

    pub fn fingerprint(&self, salt: &[u8]) -> Vec<u8> {
        self.algorithm.hmac(&self.bytes(), salt)
    }

    pub const fn get_algorithm(&self) -> Algorithm {
        self.algorithm
    }

    #[inline]
    pub const fn bytes(&self) -> &Vec<u8> {
        &self.master
    }
}

/*
// TODO: Must implement Drop

impl Drop for Master<'_> {
    fn drop(&mut self) {
        let len = self.master.len();
        let bytes = self.master.as_mut();
        for i in 0..len {
            bytes[i] = 0;
        }
    }
}*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_allow_sha1() {
        let master = Master::new("", Algorithm::SHA1);
        assert!(master.is_err());
        assert_eq!(master.err().unwrap(), LessPassError::UnsupportedAlgorithm);
    }

    #[test]
    fn passwordless_fingerprint() {
        // For keys with messages smaller than SHA256's block size (64
        // bytes), the key is padded with zeros.
        let master = Master::new("", Algorithm::SHA256).unwrap();
        assert_eq!(
            master.fingerprint(b""),
            &[
                182, 19, 103, 154, 8, 20, 217, 236, 119, 47, 149, 215, 120, 195, 95, 197, 255, 22,
                151, 196, 147, 113, 86, 83, 198, 199, 18, 20, 66, 146, 197, 173
            ]
        );
    }

    #[test]
    fn password_foo_fingerprint() {
        // For keys with messages smaller than SHA256's block size (64
        // bytes), the key is padded with zeros.
        let master = Master::new("foo", Algorithm::SHA256).unwrap();
        assert_eq!(
            master.fingerprint(b""),
            &[
                104, 55, 22, 217, 215, 248, 46, 237, 23, 76, 108, 174, 190, 8, 110, 233, 51, 118,
                199, 157, 124, 97, 221, 103, 14, 160, 15, 127, 141, 110, 176, 168
            ]
        );
    }

    #[test]
    fn password_64_bytes_length_fingerprint() {
        // It matches the block size, it is used as-is.
        let master = Master::new(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            Algorithm::SHA256,
        )
        .unwrap();
        assert_eq!(
            master.fingerprint(b""),
            &[
                8, 18, 71, 220, 104, 187, 127, 175, 191, 19, 34, 0, 19, 160, 171, 113, 219, 139,
                98, 141, 103, 145, 97, 248, 123, 94, 91, 217, 225, 155, 20, 148
            ]
        );
    }

    #[test]
    fn password_95_bytes_length_fingerprint() {
        // It is larger, it is hashed first.
        let master = Master::new("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeflarger than SHA256's block size", Algorithm::SHA256).unwrap();
        assert_eq!(
            master.fingerprint(b""),
            &[
                46, 55, 32, 12, 232, 162, 61, 209, 182, 227, 200, 183, 211, 185, 6, 171, 72, 182,
                239, 151, 196, 213, 132, 130, 106, 95, 106, 71, 156, 0, 103, 234
            ]
        );
    }

    #[test]
    fn fingerprint_with_salt() {
        let master = Master::new("password", Algorithm::SHA256).unwrap();
        assert_eq!(
            master.fingerprint(b"salt"),
            &[
                0xfc, 0x32, 0x82, 0x32, 0x99, 0x3f, 0xf3, 0x4c, 0xa5, 0x66, 0x31, 0xe4, 0xa1, 0x01,
                0xd6, 0x03, 0x93, 0xca, 0xd1, 0x21, 0x71, 0x99, 0x7e, 0xe0, 0xb5, 0x62, 0xbf, 0x78,
                0x52, 0xb2, 0xfe, 0xd0
            ]
        );
    }
}
