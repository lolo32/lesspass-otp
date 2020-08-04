use crate::{Algorithm, LessPassError};

/// Decode a base32 encoded string.
///
/// First, remove any number of `=` used for padding in `input`,
/// then remove all `-` in the string,
/// last remove all spaces
/// before trying to decode the base32.
///
/// # Examples
///
/// ```
/// use lesspass_otp::decode_base32;
///
/// let base_32 = "JBSW-Y3DP-EBLW-64TM-MQQQ";
/// let decoded = decode_base32(base_32)?;
/// assert_eq!(&decoded, b"Hello World!");
///
/// # Ok::<(), lesspass_otp::LessPassError>(())
/// ```
///
/// # Errors
///
/// Return [`LessPassError::InvalidBase32`] if the `input` is not a valid base32
/// string.
#[inline]
pub fn decode_base32(input: &str) -> Result<Vec<u8>, LessPassError> {
    let encoded = input
        .trim_end_matches(|c| c == '=')
        .replace("-", "")
        .replace(" ", "");

    let alpha = base32::Alphabet::RFC4648 { padding: false };
    match base32::decode(alpha, encoded.as_str()) {
        Some(val) => Ok(val),
        None => Err(LessPassError::InvalidBase32),
    }
}

/// Deals with the OTP authentication.
///
/// Can be used to provide `HOTP` or `TOTP`.
///
/// # Example
///
/// ```
/// use lesspass_otp::{Otp, Algorithm};
///
/// let otp = Otp::new(b"Hello World!", 6, Some(Algorithm::SHA1), None, None)?;
///
/// // To make a TOTP with current timestamp, need [feature = "std_time"]
/// let token = otp.totp();
/// // You will get something like the following line
/// //assert_eq!(token, "952840");
///
/// // To make a TOTP with custom timestamp
/// let token = otp.totp_from_ts(1_234_567_890);
/// assert_eq!(token, "575656");
///
/// // To make a HOTP
/// let token = otp.hotp(42);
/// assert_eq!(token, "063323");
///
/// # Ok::<(), lesspass_otp::LessPassError>(())
/// ```
#[derive(Debug)]
pub struct Otp {
    // Secret to use
    secret: Vec<u8>,
    // Algorithm, must be Sha1 (default), Sha2-256 or Sha2-512
    algorithm: Algorithm,
    // Number of digits, 6 (default) or 8
    digits: u8,
    // Period of validity of the token (30 secs by default)
    period: u32,
    // Timestamp delta for TOTP (0 by default)
    timestamp: u64,
}

impl Otp {
    /// Create an instance from a binary secret
    ///
    /// * create an instance from a `secret` bytes array,
    /// * producing a result of `digits` length,
    /// * using `algorithm` [`Algorithm::SHA1`], [`Algorithm::SHA256`] or [`Algorithm::SHA512`]:
    ///   _[`Algorithm::SHA1`] by default_,
    /// * with a window `period` of seconds for TOTP: _`30 seconds` by default_,
    /// * with the `timestamp` beginning step from Unix Epoch for TOTP: _`0 seconds` by default_.
    ///
    /// # Errors
    ///
    /// * [`LessPassError::InvalidLength`] if the secret length is not valid.
    ///   It must be from `6` to `9`.
    /// * [`LessPassError::UnsupportedAlgorithm`] if the specified algorithm is not supported.
    ///   It must be [`Algorithm::SHA1`] or [`Algorithm::SHA256`] or [`Algorithm::SHA512`],
    ///   anything else is invalid.
    ///
    /// # Example
    ///
    /// ```
    /// use lesspass_otp::{Otp, Algorithm};
    ///
    /// let secret = b"12345678901234567890123456789012";
    /// let otp = Otp::new(secret, 8, Some(Algorithm::SHA256), None, None).unwrap();
    /// let token = otp.totp_from_ts(59);
    ///
    /// assert_eq!(token, "46119246");
    /// ```
    pub fn new(
        secret: &[u8],
        digits: u8,
        algorithm: Option<Algorithm>,
        period: Option<u32>,
        timestamp: Option<u64>,
    ) -> Result<Self, LessPassError> {
        match (algorithm, digits) {
            // Allow valid algorithms
            (None, i)
            | (Some(Algorithm::SHA1), i)
            | (Some(Algorithm::SHA256), i)
            | (Some(Algorithm::SHA512), i)
                if i > 5 && i < 10 =>
            {
                Ok(Self {
                    secret: secret.to_vec(),
                    algorithm: algorithm.unwrap_or_else(|| Algorithm::SHA1),
                    digits,
                    period: period.unwrap_or(30).max(1),
                    timestamp: timestamp.unwrap_or(0),
                })
            }
            (None, _)
            | (Some(Algorithm::SHA1), _)
            | (Some(Algorithm::SHA256), _)
            | (Some(Algorithm::SHA512), _) => Err(LessPassError::InvalidLength),

            // Others algorithm are not supported
            _ => Err(LessPassError::UnsupportedAlgorithm),
        }
    }

    /// `[feature = "std_time"]` Retrieve the TOTP code with actual timestamp.
    #[cfg(feature = "std_time")]
    #[must_use]
    pub fn totp(&self) -> String {
        use std::time::SystemTime;

        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.totp_from_ts(time)
    }

    /// Retrieve the TOTP code with time number of seconds
    #[must_use]
    pub fn totp_from_ts(&self, timestamp: u64) -> String {
        // Pass to HTOP (same algorithm), with window timestamp as counter
        self.hotp((timestamp - self.timestamp) / u64::from(self.period))
    }

    /// Retrieve the HOTP code, with `counter` being the current value to use
    #[must_use]
    pub fn hotp(&self, counter: u64) -> String {
        // compute the HMAC of the selected algorithm
        let digest = self.algorithm.hmac(&self.secret, &counter.to_be_bytes());

        // Truncate
        let off = (digest.last().unwrap() & 0xf) as usize;
        let binary = (u64::from(digest[off]) & 0x7f) << 24
            | (u64::from(digest[off + 1]) & 0xff) << 16
            | (u64::from(digest[off + 2]) & 0xff) << 8
            | u64::from(digest[off + 3]) & 0xff;
        let binary = binary % (10_u64.pow(self.digits.into()));

        // Prepend with additional 0 to have digits length Token and convert it to String
        format!("{:0>1$}", binary, self.digits.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_decoding() {
        let s = b"Hello world!";
        assert_eq!(decode_base32("JBSWY3DPEB3W64TMMQQQ").unwrap(), s);
        assert_eq!(decode_base32("JBSWY3DPEB3W64TMMQQQ==").unwrap(), s);
        assert_eq!(decode_base32("JBSW Y3DP-EB3W 64TM-MQQQ").unwrap(), s);
    }

    #[test]
    fn allow_only_available_algorithm() {
        // Valid algorithm
        let valid = [Algorithm::SHA1, Algorithm::SHA256, Algorithm::SHA512];
        for i in valid.iter() {
            let fa2 = Otp::new(b"", 8, Some(*i), None, None);
            assert!(fa2.is_ok());
        }

        // Invalid algorithm
        let valid = [
            Algorithm::SHA384,
            Algorithm::SHA3_256,
            Algorithm::SHA3_384,
            Algorithm::SHA3_512,
        ];
        for i in valid.iter() {
            let fa2 = Otp::new(b"", 8, Some(*i), None, None);
            assert!(fa2.is_err());
            assert_eq!(fa2.err().unwrap(), LessPassError::UnsupportedAlgorithm);
        }
    }

    #[test]
    fn allow_only_valid_digits_length() {
        // Invalid length
        let len_invalid = [1_u8, 2, 3, 4, 5, 10, 11, 12, 13, 14];
        for i in len_invalid.iter() {
            let fa2 = Otp::new(b"", *i, None, None, None);
            assert!(fa2.is_err());
            assert_eq!(fa2.err().unwrap(), LessPassError::InvalidLength);
        }

        // Valid length
        for i in 6_u8..=9 {
            let fa2 = Otp::new(b"", i, None, None, None);
            assert!(fa2.is_ok());
        }
    }

    #[test]
    fn tests_vectors_rfc_sha1_8chars() {
        let seed = b"12345678901234567890";
        let t = Otp::new(seed, 8, None, None, None).unwrap();
        assert_eq!(t.totp_from_ts(59), "94287082");
        assert_eq!(t.totp_from_ts(1_111_111_109), "07081804");
        assert_eq!(t.totp_from_ts(1_111_111_111), "14050471");
        assert_eq!(t.totp_from_ts(1_234_567_890), "89005924");
        assert_eq!(t.totp_from_ts(2_000_000_000), "69279037");
        assert_eq!(t.totp_from_ts(20_000_000_000), "65353130");
    }

    #[test]
    fn tests_vectors_rfc_sha256_8chars() {
        let seed = b"12345678901234567890123456789012";
        let t = Otp::new(seed, 8, Some(Algorithm::SHA256), None, None).unwrap();
        assert_eq!(t.totp_from_ts(59), "46119246");
        assert_eq!(t.totp_from_ts(1_111_111_109), "68084774");
        assert_eq!(t.totp_from_ts(1_111_111_111), "67062674");
        assert_eq!(t.totp_from_ts(1_234_567_890), "91819424");
        assert_eq!(t.totp_from_ts(2_000_000_000), "90698825");
        assert_eq!(t.totp_from_ts(20_000_000_000), "77737706");
    }

    #[test]
    fn tests_vectors_rfc_sha512_8chars() {
        let seed = b"1234567890123456789012345678901234567890123456789012345678901234";
        let t = Otp::new(seed, 8, Some(Algorithm::SHA512), None, None).unwrap();
        assert_eq!(t.totp_from_ts(59), "90693936");
        assert_eq!(t.totp_from_ts(1_111_111_109), "25091201");
        assert_eq!(t.totp_from_ts(1_111_111_111), "99943326");
        assert_eq!(t.totp_from_ts(1_234_567_890), "93441116");
        assert_eq!(t.totp_from_ts(2_000_000_000), "38618901");
        assert_eq!(t.totp_from_ts(20_000_000_000), "47863826");
    }

    #[test]
    fn tests_vectors_rfc_sha1_6chars() {
        let seed = b"12345678901234567890";
        let t = Otp::new(seed, 6, None, None, None).unwrap();
        assert_eq!(t.hotp(0), "755224");
        assert_eq!(t.hotp(1), "287082");
        assert_eq!(t.hotp(2), "359152");
        assert_eq!(t.hotp(3), "969429");
        assert_eq!(t.hotp(4), "338314");
        assert_eq!(t.hotp(5), "254676");
        assert_eq!(t.hotp(6), "287922");
        assert_eq!(t.hotp(7), "162583");
        assert_eq!(t.hotp(8), "399871");
        assert_eq!(t.hotp(9), "520489");
    }

    #[test]
    fn totp() {
        let t = Otp::new(b"1234567890", 9, None, None, None).unwrap();
        assert_eq!(t.totp().len(), 9);
    }
}
