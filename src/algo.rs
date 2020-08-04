#![allow(non_camel_case_types)]

use core::fmt;

use hmac::{digest::FixedOutput, digest::generic_array::typenum::Unsigned, Hmac, Mac, NewMac};
use pbkdf2::pbkdf2 as pbkdf2_;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use sha3::{Sha3_256, Sha3_384, Sha3_512};

/// Selects the hash algorithm to use in PBKDF or HMAC.
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum Algorithm {
    /// SHA1.
    ///
    /// Note: Using this algorithm does not work with LessPass.
    SHA1,

    /// SHA2-256.
    ///
    /// This is the algorithm used by the canonical LessPass
    /// implementation.
    SHA256,

    /// SHA2-384.
    ///
    /// Note: Using this algorithm makes the generated passwords
    /// different from every other LessPass implementation.
    SHA384,

    /// SHA2-512.
    ///
    /// Note: Using this algorithm makes the generated passwords
    /// different from every other LessPass implementation.
    SHA512,

    /// SHA3-256.
    ///
    /// Note: Using this algorithm makes the generated passwords
    /// different from every other LessPass implementation.
    SHA3_256,

    /// SHA3-384.
    ///
    /// Note: Using this algorithm makes the generated passwords
    /// different from every other LessPass implementation.
    SHA3_384,

    /// SHA3-512.
    ///
    /// Note: Using this algorithm makes the generated passwords
    /// different from every other LessPass implementation.
    SHA3_512,
}

impl Algorithm {
    /// Derive a PBKDF2 using current [Algorithm].
    ///
    /// The result length is variable:
    /// * 20 chars for [`Algorithm::SHA1`]
    /// * 32 chars for [`Algorithm::SHA256`] or [`Algorithm::SHA3_256`]
    /// * 48 chars for [`Algorithm::SHA384`] or [`Algorithm::SHA3_384`]
    /// * 64 chars for [`Algorithm::SHA512`] or [`Algorithm::SHA3_512`]
    ///
    /// # Examples
    ///
    /// ```
    /// use lesspass_otp::Algorithm;
    ///
    /// let hash = Algorithm::SHA256.pbkdf2(b"myS3cre!K3y", b"Some salt", 1_000);
    /// assert_eq!(hash, vec![
    ///     227, 177, 151, 110, 153, 91, 123, 25, 111, 211, 151, 207, 114, 223,
    ///     7, 194, 237, 243, 155, 62, 65, 201, 210, 230, 144, 213, 91, 151, 230,
    ///     23, 64, 239
    /// ]);
    ///
    /// let hash = Algorithm::SHA3_512.pbkdf2(b"myS3cre!K3y", b"Some salt", 1_000);
    /// assert_eq!(hash, vec![
    ///     233, 252, 44, 46, 18, 219, 245, 43, 176, 221, 248, 104, 5, 226, 170,
    ///     242, 38, 161, 20, 240, 51, 167, 97, 138, 30, 222, 179, 48, 206, 169,
    ///     56, 137, 247, 111, 153, 89, 58, 40, 209, 206, 153, 227, 100, 47, 222,
    ///     255, 47, 158, 172, 175, 132, 171, 101, 109, 152, 167, 145, 232, 201,
    ///     216, 2, 137, 139, 67
    /// ]);
    /// ```
    #[must_use]
    pub fn pbkdf2(self, key: &[u8], data: &[u8], iterations: u32) -> Vec<u8> {
        macro_rules! pbkdf2_hash {
            ($hash:ty) => {
                {
                    // Length of the output array, based on $hash specified
                    let len = <$hash as FixedOutput>::OutputSize::to_usize();
                    // Initialize an array of the specific length
                    let mut hex = Vec::with_capacity(len);
                    unsafe { hex.set_len(len) };
                    // Compute the PBKDF2, based on the selected $hash
                    pbkdf2_::<Hmac<$hash>>(key, data, iterations, &mut hex.as_mut_slice());
                    // Return the array
                    hex
                }
            }
        }

        match self {
            Self::SHA1 => pbkdf2_hash!(Sha1),
            Self::SHA256 => pbkdf2_hash!(Sha256),
            Self::SHA384 => pbkdf2_hash!(Sha384),
            Self::SHA512 => pbkdf2_hash!(Sha512),
            Self::SHA3_256 => pbkdf2_hash!(Sha3_256),
            Self::SHA3_384 => pbkdf2_hash!(Sha3_384),
            Self::SHA3_512 => pbkdf2_hash!(Sha3_512),
        }
    }

    /// Derive a HMAC using current [Algorithm].
    ///
    /// The result length is variable:
    /// * 20 chars for [`Algorithm::SHA1`]
    /// * 32 chars for [`Algorithm::SHA256`] or [`Algorithm::SHA3_256`]
    /// * 48 chars for [`Algorithm::SHA384`] or [`Algorithm::SHA3_384`]
    /// * 64 chars for [`Algorithm::SHA512`] or [`Algorithm::SHA3_512`]
    ///
    /// # Examples
    ///
    /// ```
    /// use lesspass_otp::Algorithm;
    ///
    /// let hash = Algorithm::SHA384.hmac(b"myS3cre!K3y", b"Some salt");
    /// assert_eq!(hash, vec![
    ///     101, 43, 178, 21, 155, 159, 249, 65, 0, 217, 135, 141, 114, 87, 92,
    ///     89, 114, 74, 21, 79, 109, 214, 224, 231, 176, 95, 49, 94, 175, 109,
    ///     87,82, 227, 88, 147, 14, 36, 84, 252, 11, 236, 112, 54, 245, 131,
    ///     79, 184, 217
    /// ]);
    ///
    /// let hash = Algorithm::SHA1.hmac(b"myS3cre!K3y", b"Some salt");
    /// assert_eq!(hash, vec![
    ///     232, 193, 68, 5, 132, 230, 202, 21, 208, 227, 112, 255, 88, 91,
    ///     187, 37, 60, 193, 236, 34
    /// ]);
    /// ```
    #[must_use]
    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        macro_rules! hmac_hash {
            ($hash:ty) => {
                {
                    // Create the HMAC
                    let mut mac = <Hmac<$hash>>::new_varkey(key).expect("Hmac creation failed");
                    // Do the hashing
                    mac.update(data);
                    // Return the result
                    mac.finalize().into_bytes().to_vec()
                }
            }
        }
        match self {
            Self::SHA1 => hmac_hash!(Sha1),
            Self::SHA256 => hmac_hash!(Sha256),
            Self::SHA384 => hmac_hash!(Sha384),
            Self::SHA512 => hmac_hash!(Sha512),
            Self::SHA3_256 => hmac_hash!(Sha3_256),
            Self::SHA3_384 => hmac_hash!(Sha3_384),
            Self::SHA3_512 => hmac_hash!(Sha3_512),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SHA1 => "Sha1",
            Self::SHA256 => "Sha2-256",
            Self::SHA384 => "Sha2-384",
            Self::SHA512 => "Sha2-512",
            Self::SHA3_256 => "Sha3-256",
            Self::SHA3_384 => "Sha3-384",
            Self::SHA3_512 => "Sha3-512",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_correct_to_string() {
        assert_eq!(Algorithm::SHA256.to_string(), "Sha2-256");
        assert_eq!(Algorithm::SHA384.to_string(), "Sha2-384");
        assert_eq!(Algorithm::SHA512.to_string(), "Sha2-512");
        assert_eq!(Algorithm::SHA3_256.to_string(), "Sha3-256");
        assert_eq!(Algorithm::SHA3_384.to_string(), "Sha3-384");
        assert_eq!(Algorithm::SHA3_512.to_string(), "Sha3-512");
    }

    #[test]
    fn check_rfc_hmac() {
        assert_eq!(
            Algorithm::SHA1.hmac(b"Jefe", b"what do ya want for nothing?"),
            [
                0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
                0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79
            ]
            .to_vec()
        );
        assert_eq!(
            Algorithm::SHA256.hmac(b"Jefe", b"what do ya want for nothing?"),
            [
                0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
                0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
                0x64, 0xec, 0x38, 0x43
            ]
            .to_vec()
        );
        assert_eq!(
            Algorithm::SHA384.hmac(b"Jefe", b"what do ya want for nothing?"),
            [
                0xaf, 0x45, 0xd2, 0xe3, 0x76, 0x48, 0x40, 0x31, 0x61, 0x7f, 0x78, 0xd2, 0xb5, 0x8a,
                0x6b, 0x1b, 0x9c, 0x7e, 0xf4, 0x64, 0xf5, 0xa0, 0x1b, 0x47, 0xe4, 0x2e, 0xc3, 0x73,
                0x63, 0x22, 0x44, 0x5e, 0x8e, 0x22, 0x40, 0xca, 0x5e, 0x69, 0xe2, 0xc7, 0x8b, 0x32,
                0x39, 0xec, 0xfa, 0xb2, 0x16, 0x49
            ]
            .to_vec()
        );
        assert_eq!(
            Algorithm::SHA512.hmac(b"Jefe", b"what do ya want for nothing?"),
            [
                0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7, 0x3b, 0x56,
                0xe0, 0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6, 0x10, 0x27, 0x0c, 0xd7,
                0xea, 0x25, 0x05, 0x54, 0x97, 0x58, 0xbf, 0x75, 0xc0, 0x5a, 0x99, 0x4a, 0x6d, 0x03,
                0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd, 0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b,
                0x63, 0x6e, 0x07, 0x0a, 0x38, 0xbc, 0xe7, 0x37
            ]
            .to_vec()
        );
        assert_eq!(
            Algorithm::SHA3_256.hmac(b"Jefe", b"what do ya want for nothing?"),
            [
                0xc7, 0xd4, 0x07, 0x2e, 0x78, 0x88, 0x77, 0xae, 0x35, 0x96, 0xbb, 0xb0, 0xda, 0x73,
                0xb8, 0x87, 0xc9, 0x17, 0x1f, 0x93, 0x09, 0x5b, 0x29, 0x4a, 0xe8, 0x57, 0xfb, 0xe2,
                0x64, 0x5e, 0x1b, 0xa5
            ]
            .to_vec()
        );
        assert_eq!(
            Algorithm::SHA3_384.hmac(b"Jefe", b"what do ya want for nothing?"),
            [
                0xf1, 0x10, 0x1f, 0x8c, 0xbf, 0x97, 0x66, 0xfd, 0x67, 0x64, 0xd2, 0xed, 0x61, 0x90,
                0x3f, 0x21, 0xca, 0x9b, 0x18, 0xf5, 0x7c, 0xf3, 0xe1, 0xa2, 0x3c, 0xa1, 0x35, 0x08,
                0xa9, 0x32, 0x43, 0xce, 0x48, 0xc0, 0x45, 0xdc, 0x00, 0x7f, 0x26, 0xa2, 0x1b, 0x3f,
                0x5e, 0x0e, 0x9d, 0xf4, 0xc2, 0x0a
            ]
            .to_vec()
        );
        assert_eq!(
            Algorithm::SHA3_512.hmac(b"Jefe", b"what do ya want for nothing?"),
            [
                0x5a, 0x4b, 0xfe, 0xab, 0x61, 0x66, 0x42, 0x7c, 0x7a, 0x36, 0x47, 0xb7, 0x47, 0x29,
                0x2b, 0x83, 0x84, 0x53, 0x7c, 0xdb, 0x89, 0xaf, 0xb3, 0xbf, 0x56, 0x65, 0xe4, 0xc5,
                0xe7, 0x09, 0x35, 0x0b, 0x28, 0x7b, 0xae, 0xc9, 0x21, 0xfd, 0x7c, 0xa0, 0xee, 0x7a,
                0x0c, 0x31, 0xd0, 0x22, 0xa9, 0x5e, 0x1f, 0xc9, 0x2b, 0xa9, 0xd7, 0x7d, 0xf8, 0x83,
                0x96, 0x02, 0x75, 0xbe, 0xb4, 0xe6, 0x20, 0x24
            ]
            .to_vec()
        );
    }

    #[test]
    fn tests_rfc_pbkdf2() {
        assert_eq!(
            Algorithm::SHA1.pbkdf2(b"password", b"salt", 4096),
            [
                0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7,
                0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1
            ]
                .to_vec()
        );
        assert_eq!(
            Algorithm::SHA256.pbkdf2(b"password", b"salt", 4096),
            [
                0xc5, 0xe4, 0x78, 0xd5, 0x92, 0x88, 0xc8, 0x41, 0xaa, 0x53, 0x0d, 0xb6, 0x84, 0x5c,
                0x4c, 0x8d, 0x96, 0x28, 0x93, 0xa0, 0x01, 0xce, 0x4e, 0x11, 0xa4, 0x96, 0x38, 0x73,
                0xaa, 0x98, 0x13, 0x4a
            ]
                .to_vec()
        );
        assert_eq!(
            Algorithm::SHA384.pbkdf2(b"password", b"salt", 4096),
            [
                0x55, 0x97, 0x26, 0xbe, 0x38, 0xdb, 0x12, 0x5b, 0xc8, 0x5e, 0xd7, 0x89, 0x5f, 0x6e,
                0x3c, 0xf5, 0x74, 0xc7, 0xa0, 0x1c, 0x08, 0x0c, 0x34, 0x47, 0xdb, 0x1e, 0x8a, 0x76,
                0x76, 0x4d, 0xeb, 0x3c, 0x30, 0x7b, 0x94, 0x85, 0x3f, 0xbe, 0x42, 0x4f, 0x64, 0x88,
                0xc5, 0xf4, 0xf1, 0x28, 0x96, 0x26
            ]
                .to_vec()
        );
        assert_eq!(
            Algorithm::SHA512.pbkdf2(b"password", b"salt", 4096),
            [
                0xd1, 0x97, 0xb1, 0xb3, 0x3d, 0xb0, 0x14, 0x3e, 0x01, 0x8b, 0x12, 0xf3, 0xd1, 0xd1,
                0x47, 0x9e, 0x6c, 0xde, 0xbd, 0xcc, 0x97, 0xc5, 0xc0, 0xf8, 0x7f, 0x69, 0x02, 0xe0,
                0x72, 0xf4, 0x57, 0xb5, 0x14, 0x3f, 0x30, 0x60, 0x26, 0x41, 0xb3, 0xd5, 0x5c, 0xd3,
                0x35, 0x98, 0x8c, 0xb3, 0x6b, 0x84, 0x37, 0x60, 0x60, 0xec, 0xd5, 0x32, 0xe0, 0x39,
                0xb7, 0x42, 0xa2, 0x39, 0x43, 0x4a, 0xf2, 0xd5
            ]
                .to_vec()
        );
        assert_eq!(
            Algorithm::SHA3_256.pbkdf2(b"password", b"salt", 4096),
            [
                0x77, 0x8b, 0x6e, 0x23, 0x7a, 0x0f, 0x49, 0x62, 0x15, 0x49, 0xff, 0x70, 0xd2, 0x18,
                0xd2, 0x08, 0x07, 0x56, 0xb9, 0xfb, 0x38, 0xd7, 0x1b, 0x5d, 0x7e, 0xf4, 0x47, 0xfa,
                0x22, 0x54, 0xaf, 0x61
            ]
                .to_vec()
        );
        assert_eq!(
            Algorithm::SHA3_384.pbkdf2(b"password", b"salt", 4096),
            [
                0x9a, 0x5f, 0x1e, 0x45, 0xe8, 0xb8, 0x3f, 0x1b, 0x25, 0x9b, 0xa7, 0x2d, 0x11, 0xc5,
                0x90, 0x87, 0x01, 0xb8, 0x67, 0x8b, 0x86, 0xf0, 0x1d, 0x81, 0x19, 0x67, 0x71, 0x81,
                0x8e, 0x61, 0x4d, 0x01, 0x79, 0x7d, 0x3d, 0x5a, 0xc4, 0x40, 0x43, 0x5f, 0x00, 0x20,
                0x9c, 0xae, 0x87, 0x23, 0xc5, 0x8c
            ]
                .to_vec()
        );
        assert_eq!(
            Algorithm::SHA3_512.pbkdf2(b"password", b"salt", 4096),
            [
                0x2b, 0xfa, 0xf2, 0xd5, 0xce, 0xb6, 0xd1, 0x0f, 0x5e, 0x26, 0x2c, 0xd9, 0x02, 0x48,
                0x8c, 0xfd, 0x44, 0x89, 0x61, 0x4e, 0xcd, 0x67, 0x09, 0xe5, 0xee, 0x39, 0x5d, 0xc3,
                0x3f, 0x2e, 0x9a, 0xd7, 0xf8, 0x9d, 0x31, 0xad, 0x67, 0x81, 0xe9, 0x09, 0x40, 0xe9,
                0xe5, 0x34, 0xff, 0x44, 0xb8, 0x17, 0x15, 0x9d, 0xdc, 0xd3, 0xbd, 0xce, 0x33, 0x73,
                0x54, 0x11, 0x86, 0xb7, 0x27, 0x34, 0x02, 0x31
            ]
                .to_vec()
        );
    }
}
