#![deny(missing_docs)]
#![deny(missing_copy_implementations)]
#![deny(missing_debug_implementations)]
#![deny(trivial_numeric_casts)]
#![deny(unreachable_pub)]
#![deny(unsafe_code)]
#![deny(unused_extern_crates)]
#![deny(unused_qualifications)]
#![doc(
    test(no_crate_inject, attr(deny(warnings))),
    test(attr(allow(unused_variables))),
    html_no_source
)]
#![deny(
    missing_copy_implementations,
    missing_docs,
    missing_debug_implementations,
    single_use_lifetimes,
    unsafe_code,
    unused_extern_crates,
    unused_import_braces,
    unused_lifetimes,
    unused_qualifications,
    unused_results,
    clippy::all,
    clippy::pedantic,
    clippy::nursery
)]
#![allow(clippy::cast_possible_truncation, clippy::redundant_pub_crate)]
// Clippy rules in the `Restriction lints`
#![deny(
    clippy::clone_on_ref_ptr,
    clippy::create_dir,
    clippy::dbg_macro,
    clippy::decimal_literal_representation,
    clippy::else_if_without_else,
    clippy::exit,
    clippy::filetype_is_file,
    clippy::float_arithmetic,
    clippy::float_cmp_const,
    clippy::get_unwrap,
    clippy::inline_asm_x86_att_syntax,
    clippy::inline_asm_x86_intel_syntax,
    clippy::let_underscore_must_use,
    clippy::lossy_float_literal,
    clippy::map_err_ignore,
    clippy::mem_forget,
    clippy::missing_docs_in_private_items,
    clippy::modulo_arithmetic,
    clippy::multiple_inherent_impl,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::pattern_type_mismatch,
    clippy::print_stderr,
    clippy::print_stdout,
    clippy::rc_buffer,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::shadow_same,
    clippy::str_to_string,
    clippy::string_to_string,
    clippy::todo,
    clippy::unimplemented,
    clippy::unneeded_field_pattern,
    clippy::unwrap_used,
    clippy::use_debug,
    clippy::verbose_file_reads,
    clippy::wildcard_enum_match_arm,
    clippy::wrong_pub_self_convention
)]

//! This crate can be used to generate password for any site, with only a master password,
//! a site name, a login and a counter. Generate TOTP or HOTP too.
//!
//! All the generated password are derived from a master password,
//! __that you are the only one to know__,
//! a site url,
//! a username
//! and of course, because these parameters cannot be changed,
//! a counter to increment to change the password on the site.
//! It's possible to change the password length and the characters set to use
//! (lowercase, uppercase, numbers and/or symbols).
//!
//! # Examples
//!
//! ```
//! use lesspass_otp::{Algorithm, LessPass, Otp, Settings};
//! use lesspass_otp::charset::CharacterSet;
//!
//! // ------------------
//! // Initialise the library
//! let master = LessPass::new("mY5ecr3!", Algorithm::SHA256)?;
//!
//! // ------------------
//! // Check the master password is valid, with fingerprint
//! // Can be printed publicly
//! let fingerprint = master.get_fingerprint(b"");
//! assert_eq!(fingerprint, [
//!         ("#24FE23", "fa-car"),
//!         ("#DB6D00", "fa-certificate"),
//!         ("#B66DFF", "fa-gbp")
//! ]);
//!
//! // ------------------
//! // 16 chars, and lower + upper + number + symbol
//! let settings = Settings::default();
//! // 20 chars, and lower + upper + number
//! let settings = Settings::new(20, CharacterSet::LowercaseUppercaseNumbers);
//!
//! // ------------------
//! // Generate a password
//! let password = master.password("facebook.com", "test@example.com", 42, &settings)?;
//! assert_eq!(password, "BJwptmUpz2bEWHM9NA48");
//!
//! // ------------------
//! // Retrieve a TOTP
//! let otp_secret = b"gfE%Tgd56^&!gd$";
//! let otp = Otp::new(otp_secret, 6, Some(Algorithm::SHA512), Some(30), Some(0))?;
//! // Get token from timestamp (require [feature = "std_time"])
//! let token = otp.totp();
//! // Get token from predefined timestamp
//! let token = otp.totp_from_ts(1_234_567_890);
//! assert_eq!(token, "586893");
//!
//! // ------------------
//! // Encrypt a HOTP before storing it
//! # fn store_otp_secret(_secret: &[u8]) {}
//! let encrypted = master.secret_totp("github.com", "test@example.com", otp_secret)?;
//! assert_eq!(encrypted, &[
//!         255, 37, 183, 103, 211, 97, 25, 139, 84, 212, 123,
//!         123, 188, 58, 183, 111, 25, 79, 163, 101, 255, 155,
//!         174, 184, 12, 99, 200, 15, 246, 37, 204, 108
//! ]);
//! // Store the encrypted token, it cannot be recovered without master password,
//! // website and username
//! store_otp_secret(&encrypted);
//!
//! // ------------------
//! // Decode OTP secret
//! # let retrieve_otp_secret = || encrypted;
//! let encrypted = retrieve_otp_secret();
//!
//! // Wrong login information, secret cannot be retrieved
//! let wrong_decrypted = master.secret_totp("facebook.com", "test@example.com", &encrypted)?;
//! assert_ne!(encrypted.to_vec(), wrong_decrypted);
//! let master2 = LessPass::new("pass", Algorithm::SHA256)?;
//! let wrong_decrypted = master2.secret_totp("github.com", "test@example.com", &encrypted)?;
//! assert_ne!(encrypted.to_vec(), wrong_decrypted);
//!
//! // Correct information
//! let decrypted = master.secret_totp("github.com", "test@example.com", &encrypted)?;
//! assert_eq!(decrypted, otp_secret);
//!
//! # Ok::<(), lesspass_otp::LessPassError>(())
//! ```

use std::ops::Sub;

#[macro_use]
extern crate lazy_static;

use num_bigint::BigUint;

use crate::master::Master;
pub use crate::{
    algo::Algorithm,
    charset::{CharUse, CharacterSet, Set},
    entropy::Entropy,
    errors::LessPassError,
    fingerprint::Fingerprint,
    otp::{decode_base32, encode_base32, Otp},
    settings::Settings,
};

/// Algorythm implementations
mod algo;
/// Settings to define charset.
pub mod charset;
/// Entropy generator
mod entropy;
/// Errors
mod errors;
/// Password fingerprint
mod fingerprint;
/// Hexadecimal
mod hex;
/// Master password
mod master;
/// TOTP and HTOP
mod otp;
/// Settings
mod settings;

/// Result type with integrated error from the crate
pub type Result<T> = core::result::Result<T, LessPassError>;

/// The main struct, this is where we define the master password.
#[derive(Debug, Clone)]
pub struct LessPass {
    /// Master password
    master: Master,
}

lazy_static! {
    static ref BIGINT1: BigUint = BigUint::from(1_u64);
}

impl LessPass {
    /// Define master password to be used with every password.
    ///
    /// The algorithm is the one used to generate the fingerprint, and the one
    /// used by default with password without algorithm specified.
    ///
    /// # Examples
    ///
    /// ```
    /// use lesspass_otp::{Algorithm, LessPass};
    ///
    /// let lp = LessPass::new("My5ecr3!", Algorithm::SHA256)?;
    ///
    /// # Ok::<(), lesspass_otp::LessPassError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Could return a [`LessPassError::UnsupportedAlgorithm`] if the provided algorithm
    /// is not supported.
    pub fn new(master: &str, algorithm: Algorithm) -> Result<Self> {
        Ok(Self {
            master: Master::new(master, algorithm)?,
        })
    }

    /// Derive a password from the settings provided in the initialisation and identifications
    /// of the current site.
    ///
    /// # Examples
    ///
    /// ```
    /// use lesspass_otp::{Algorithm, LessPass, Settings};
    ///
    /// let lp = LessPass::new("My5ecr3!", Algorithm::SHA256)?;
    /// // 16 characters, SHA2-256, lower, upper, number and symbol
    /// let settings = Settings::default();
    ///
    /// let pass = lp.password("example.com", "test@example.com", 1, &settings)?;
    /// assert_eq!(pass, "38VdYgV3)/x*}`e,");
    ///
    /// # Ok::<(), lesspass_otp::LessPassError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// * [`LessPassError::NoCharsetSelected`] if no characters are asked in the resulting
    ///   password.
    /// * [`LessPassError::PasswordTooLong`] if the requested password length is too long
    ///   for the current algorithm.
    /// * [`LessPassError::PasswordTooShort`] if the requested password is too short:
    ///   less than 5 characters is forbidden.
    /// * [`LessPassError::UnsupportedAlgorithm`] in case you want to use an unsupported
    ///   algorithm.
    pub fn password(
        &self,
        site: &str,
        login: &str,
        counter: u32,
        settings: &Settings,
    ) -> Result<String> {
        // Validate parameters settings
        let algorithm = settings
            .get_algorithm()
            .unwrap_or_else(|| self.master.get_algorithm());
        // Validate the algorithm and password length
        match (algorithm, settings.get_password_len()) {
            // Sha1 cannot be used with LessPass
            (Algorithm::SHA1, _) => return Err(LessPassError::UnsupportedAlgorithm),

            // Password length need to be more than 5 characters
            (_, i) if i < 5 => return Err(LessPassError::PasswordTooShort(5, i)),

            // SHA-512 and SHA3-512, accept password length up to 70 characters
            (Algorithm::SHA512, i) | (Algorithm::SHA3_512, i) if i > 70 => {
                return Err(LessPassError::PasswordTooLong(70, i, algorithm));
            }
            (Algorithm::SHA512, _) | (Algorithm::SHA3_512, _) => {} // OK

            // SHA-384 and SHA3-384, accept password length up to 52 characters
            (Algorithm::SHA384, i) | (Algorithm::SHA3_384, i) if i > 52 => {
                return Err(LessPassError::PasswordTooLong(52, i, algorithm));
            }
            (Algorithm::SHA384, _) | (Algorithm::SHA3_384, _) => {} // OK

            // others algorithms accept password length up to 35 characters
            (Algorithm::SHA256, i) | (Algorithm::SHA3_256, i) if i > 35 => {
                return Err(LessPassError::PasswordTooLong(35, i, algorithm));
            }
            (Algorithm::SHA256, _) | (Algorithm::SHA3_256, _) => {} // OK
        }

        if settings.get_characterset().get_charset_count() == 0 {
            return Err(LessPassError::NoCharsetSelected);
        }

        // Generate salt
        let salt = Entropy::salt(site, login, counter);
        // Calculate entropy
        let mut entropy = Entropy::new(algorithm, &self.master, &salt, settings.get_iterations());

        // Generate the password now that all prerequisite is available

        let charset = settings.get_characterset();
        let chars = charset.get_chars();
        let chars = chars.as_bytes();
        let max_len = (settings.get_password_len() as usize).sub(charset.get_charset_count());
        let charset_len = BigUint::from(chars.len());
        let mut password = Vec::with_capacity(settings.get_password_len() as usize);

        // Step 1:
        // get random char from charset, of password_len - number_of_charset length to generate a
        // temporary password
        for _ in 0..max_len {
            let rem = entropy.consume(&charset_len);
            password.push(chars[rem]);
        }

        // Step 2:
        // get one character per charset to add later to the password to add later to the
        // temporary password
        let mut additional_pass = Vec::with_capacity(charset.get_serials().len());
        for serial in charset.get_serials() {
            let rem = entropy.consume(&CharacterSet::serial_len(*serial));
            additional_pass.push(CharacterSet::get_serial(*serial).as_bytes()[rem])
        }

        // Step 3:
        // add additional characters to the password to generate final password
        let mut password_len = BigUint::from(password.len());
        for char in additional_pass {
            let rem = entropy.consume(&password_len);
            password.insert(rem, char);
            password_len += &BIGINT1 as &BigUint;
        }

        Ok(String::from_utf8(password)?)
    }

    /// Generate a password, with the algorithm calculated based on password result length
    ///
    /// # Errors
    /// See `[password()]`
    pub async fn fut_password_with_algorithm_from_length(
        &self,
        site: &str,
        login: &str,
        counter: u32,
        settings: &Settings,
    ) -> Result<String> {
        self.password_with_algorithm_from_length(site, login, counter, settings)
    }

    /// Generate a password, with the algorithm calculated based on password result length
    ///
    /// # Errors
    /// See `[password()]`
    pub fn password_with_algorithm_from_length(
        &self,
        site: &str,
        login: &str,
        counter: u32,
        settings: &Settings,
    ) -> Result<String> {
        let mut settings = *settings;
        settings.set_algorithm(match settings.get_password_len() {
            l if l <= 35 => Algorithm::SHA256,
            l if l <= 52 => Algorithm::SHA384,
            _ => Algorithm::SHA512,
        });
        self.password(site, login, counter, &settings)
    }

    /// Decode a HOTP secret from aa previous encoded secret, or encode a clear one.
    ///
    /// # Note
    ///
    /// This is not possible to encrypt a secret that is either 32 or 64 characters length,
    /// the secret will be considerated as encrypted and it will try to decrypt it.
    ///
    /// # Examples
    ///
    /// ```
    /// use lesspass_otp::{Algorithm, decode_base32, LessPass, Settings};
    /// # fn store_password(_secret: &[u8]) {}
    ///
    /// let lp = LessPass::new("My5ecr3!", Algorithm::SHA256)?;
    /// let settings = Settings::default();
    ///
    /// // ----------------------
    /// // Base32 decode the secret from the website
    /// let secret = "JBSW Y3DP EBLW 64TM MQQQ";
    /// let clear = decode_base32(secret).unwrap();
    /// assert_eq!(clear, vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33]);
    ///
    /// // Encrypt the secret
    /// let encrypted_secret = lp.secret_hotp("example.com", "test@example.com", &clear)?;
    /// assert_eq!(encrypted_secret, vec![
    ///         101, 22, 162, 221, 2, 88, 94, 95, 176, 106, 204,
    ///         94, 79, 92, 141, 190, 131, 49, 214, 61, 222, 201,
    ///         120, 5, 188, 218, 35, 46, 210, 196, 21, 184
    /// ]);
    /// // store the encrypted_secret anywhere, it cannot decrypted without master password
    /// store_password(&encrypted_secret);
    ///
    /// # Ok::<(), lesspass_otp::LessPassError>(())
    /// ```
    ///
    /// Decrypt the secret, then use it:
    /// ```
    /// use lesspass_otp::{Algorithm, LessPass, Otp};
    /// # fn get_stored_encrypted_password() -> Vec<u8> {
    /// #     vec![
    /// #         101, 22, 162, 221, 2, 88, 94, 95, 176, 106, 204,
    /// #         94, 79, 92, 141, 190, 131, 49, 214, 61, 222, 201,
    /// #         120, 5, 188, 218, 35, 46, 210, 196, 21, 184
    /// #     ]
    /// # }
    ///
    /// // Retrieve the encrypted password
    /// let encrypted_secret = get_stored_encrypted_password();
    /// // Initialise with the same master password
    /// let lp = LessPass::new("My5ecr3!", Algorithm::SHA256)?;
    ///
    /// // ----------------------
    /// // Decrypt the stored encrypted secret
    /// let clear_password = lp.secret_hotp("example.com", "test@example.com", &encrypted_secret)?;
    /// assert_eq!(clear_password, vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33]);
    /// // Use the clear_password with Otp::hotp in example
    /// let otp = Otp::new(&clear_password, 6, None, None, None)?;
    /// let token = otp.hotp(42);
    /// assert_eq!(token, "063323");
    ///
    /// # Ok::<(), lesspass_otp::LessPassError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Return the error [`LessPassError::InvalidLength`] if the secret is 0 or more than
    /// 64 characters length.
    pub fn secret_hotp(&self, site: &str, login: &str, secret: &[u8]) -> Result<Vec<u8>> {
        self.secret_otp(b"hotp", site.as_bytes(), login.as_bytes(), secret)
    }
    /// Decode a TOTP secret from aa previous encoded secret, or encode a clear one.
    ///
    /// # Note
    ///
    /// This is not possible to encrypt a secret that is either 32 or 64 characters length,
    /// the secret will be considerated as encrypted and it will try to decrypt it.
    ///
    /// # Examples
    ///
    /// Encrypt the secret:
    ///
    /// ```
    /// use lesspass_otp::{Algorithm, decode_base32, LessPass};
    /// # fn store_password(_secret: &[u8]) {}
    ///
    /// let lp = LessPass::new("My5ecr3!", Algorithm::SHA256)?;
    ///
    /// // ----------------------
    /// // Base32 decode the secret from the website
    /// let secret = "JBSW Y3DP EBLW 64TM MQQQ";
    /// let clear = decode_base32(secret).unwrap();
    /// assert_eq!(clear, vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33]);
    ///
    /// // Encrypt the secret
    /// let encrypted_secret = lp.secret_totp("example.com", "test@example.com", &clear)?;
    /// assert_eq!(encrypted_secret, vec![
    ///         245, 248, 155, 215, 234, 198, 151, 5, 95, 75, 83,
    ///         152, 159, 242, 191, 223, 59, 194, 6, 233, 107, 52,
    ///         179, 27, 217, 250, 189, 86, 115, 118, 22, 138
    /// ]);
    /// // store the encrypted_secret anywhere, it cannot be decrypted without master password
    /// store_password(&encrypted_secret);
    ///
    /// # Ok::<(), lesspass_otp::LessPassError>(())
    /// ```
    ///
    /// Decrypt the secret, then use it:
    /// ```
    /// use lesspass_otp::{Algorithm, LessPass, Otp};
    /// # fn get_stored_encrypted_password() -> Vec<u8> {
    /// #     vec![
    /// #         245, 248, 155, 215, 234, 198, 151, 5, 95, 75, 83,
    /// #         152, 159, 242, 191, 223, 59, 194, 6, 233, 107, 52,
    /// #         179, 27, 217, 250, 189, 86, 115, 118, 22, 138
    /// #     ]
    /// # }
    ///
    /// // Retrieve the encrypted password
    /// let encrypted_secret = get_stored_encrypted_password();
    /// // Initialise with the same master password
    /// let lp = LessPass::new("My5ecr3!", Algorithm::SHA256)?;
    ///
    /// // ----------------------
    /// // Decrypt the stored encrypted secret
    /// let clear_password = lp.secret_totp("example.com", "test@example.com", &encrypted_secret)?;
    /// assert_eq!(clear_password, vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33]);
    /// // Use the clear_password with Otp::totp in example
    /// let otp = Otp::new(&clear_password, 6, None, None, None)?;
    /// let token = otp.totp();
    ///
    /// # Ok::<(), lesspass_otp::LessPassError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Return the error [`LessPassError::InvalidLength`] if the secret is 0 or more than
    /// 64 characters length.
    pub fn secret_totp(&self, site: &str, login: &str, secret: &[u8]) -> Result<Vec<u8>> {
        self.secret_otp(b"totp", site.as_bytes(), login.as_bytes(), secret)
    }
    /// Generic implementation used internally by `secret_totp` and `secret_hotp`
    ///
    /// # Errors
    ///
    /// `[LessPassError::InvalidLength]` if the `secret` is in an invalid length
    pub fn secret_otp(
        &self,
        prefix: &[u8],
        site: &[u8],
        login: &[u8],
        secret: &[u8],
    ) -> Result<Vec<u8>> {
        let (algorithm, encrypt) = match secret.len() {
            i if (1..32).contains(&i) => (Algorithm::SHA256, true),
            i if i == 32 => (Algorithm::SHA256, false),
            i if (33..64).contains(&i) => (Algorithm::SHA512, true),
            i if i == 64 => (Algorithm::SHA512, false),
            _ => return Err(LessPassError::InvalidLength),
        };

        let salt = Entropy::salt_byte(prefix, site, login);
        let mut hash = algorithm.pbkdf2(self.master.bytes(), &salt, 100_000);

        let len = hash.len().sub(1);

        // Get the start point to encode the information
        let start = (hash.last().expect("last byte") & len as u8) as usize;

        Ok(if encrypt {
            // Store the length of the secret
            hash[len] ^= secret.len() as u8;

            for (i, byte) in secret.iter().enumerate() {
                let pos = (start + i) % len;
                hash[pos] ^= *byte;
            }

            hash
        } else {
            let mut decrypted = Vec::new();
            let pass_length = (secret.last().expect("last byte") ^ hash[len]) as usize;
            for i in 0..pass_length {
                let pos = (start + i) % len;
                decrypted.push(hash[pos] ^ secret[pos]);
            }

            decrypted
        })
    }

    /// Get master password fingerprint.
    ///
    /// It contains an array of 3 symbols and 3 colors.
    ///
    /// # Examples
    ///
    /// ```
    /// use lesspass_otp::{Algorithm, LessPass};
    ///
    /// let lp = LessPass::new("My5ecr3!", Algorithm::SHA256)?;
    /// let fingerprint = lp.get_fingerprint(b"");
    /// assert_eq!(fingerprint, [
    ///     ("#FF6CB6", "fa-beer"),
    ///     ("#006CDB", "fa-hashtag"),
    ///     ("#FFB5DA", "fa-cutlery"),
    /// ]);
    ///
    /// # Ok::<(), lesspass_otp::LessPassError>(())
    /// ```
    #[must_use]
    pub fn get_fingerprint(&self, salt: &[u8]) -> Fingerprint {
        use crate::fingerprint::get;
        use core::fmt::Write;

        let finger = self.master.fingerprint(salt);
        let mut s = String::new();
        for &byte in &finger {
            write!(&mut s, "{:X}", byte).unwrap();
        }
        get(s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::charset::CharacterSet;

    use super::*;

    #[test]
    fn generate_password_fullcase() {
        let lesspass = LessPass::new("test@lesspass.com", Algorithm::SHA256).expect("lesspass");
        let _fing = lesspass.get_fingerprint(b"");

        let settings = Settings::new(16, CharacterSet::LowercaseUppercaseNumbersSymbols);
        let pass = lesspass.password("lesspass.com", "test@lesspass.com", 1, &settings);
        assert_eq!(pass.expect("password"), String::from("hjV@\\5ULp3bIs,6B"));
    }

    #[test]
    fn generate_password_without_lower() {
        let lesspass = LessPass::new("test@lesspass.com", Algorithm::SHA256).expect("lasspass");
        let _fing = lesspass.get_fingerprint(b"");

        let settings = Settings::new(16, CharacterSet::UppercaseNumbersSymbols);
        let pass = lesspass.password("lesspass.com", "test@lesspass.com", 1, &settings);
        assert_eq!(pass.expect("password"), String::from("^>_9>+}OV?[3[_U,"));
    }

    #[test]
    fn too_short() {
        let lesspass = LessPass::new("password", Algorithm::SHA256).expect("lesspass");
        let settings = Settings::new(4, CharacterSet::LowercaseUppercaseNumbersSymbols);
        let pass = lesspass.password("site", "login", 1, &settings);
        assert!(pass.is_err());
        assert_eq!(
            pass.err().expect("error"),
            LessPassError::PasswordTooShort(5, 4)
        );
    }

    #[test]
    fn too_long() {
        let lesspass = LessPass::new("password", Algorithm::SHA256).expect("lesspass");
        let mut settings = Settings::new(99, CharacterSet::LowercaseUppercaseNumbersSymbols);

        settings.set_algorithm(Algorithm::SHA256);
        let pass = lesspass.password("site", "login", 1, &settings);
        assert!(pass.is_err());
        assert_eq!(
            pass.err().expect("error"),
            LessPassError::PasswordTooLong(35, 99, Algorithm::SHA256)
        );

        settings.set_algorithm(Algorithm::SHA3_256);
        let pass = lesspass.password("site", "login", 1, &settings);
        assert!(pass.is_err());
        assert_eq!(
            pass.err().expect("error"),
            LessPassError::PasswordTooLong(35, 99, Algorithm::SHA3_256)
        );

        settings.set_algorithm(Algorithm::SHA384);
        let pass = lesspass.password("site", "login", 1, &settings);
        assert!(pass.is_err());
        assert_eq!(
            pass.err().expect("error"),
            LessPassError::PasswordTooLong(52, 99, Algorithm::SHA384)
        );

        settings.set_algorithm(Algorithm::SHA3_384);
        let pass = lesspass.password("site", "login", 1, &settings);
        assert!(pass.is_err());
        assert_eq!(
            pass.err().expect("error"),
            LessPassError::PasswordTooLong(52, 99, Algorithm::SHA3_384)
        );

        settings.set_algorithm(Algorithm::SHA512);
        let pass = lesspass.password("site", "login", 1, &settings);
        assert!(pass.is_err());
        assert_eq!(
            pass.err().expect("error"),
            LessPassError::PasswordTooLong(70, 99, Algorithm::SHA512)
        );

        settings.set_algorithm(Algorithm::SHA3_512);
        let pass = lesspass.password("site", "login", 1, &settings);
        assert!(pass.is_err());
        assert_eq!(
            pass.err().expect("error"),
            LessPassError::PasswordTooLong(70, 99, Algorithm::SHA3_512)
        );
    }

    #[test]
    fn otp_encrypt_decrypt() {
        let secret = &[
            0x30, 0x41, 0x71, 0x67, 0x2B, 0x59, 0x4F, 0x5A, 0x35, 0x31, 0xA7, 0x53, 0x54, 0x4B,
            0x74, 0x35, 0x4E, 0x6D, 0x36, 0x66,
        ];
        let master = LessPass::new("123", Algorithm::SHA256).expect("lesspass");
        let encrypted = master
            .secret_totp("example.com", "test@example.com", secret)
            .expect("encrypted otp");
        assert_eq!(encrypted.len(), 32);
        let decrypted = master
            .secret_totp("example.com", "test@example.com", &encrypted)
            .expect("decrypted otp");

        assert_eq!(secret.to_vec(), decrypted);
    }

    #[test]
    fn hotp_encrypt_decrypt_512() {
        let master = LessPass::new("DEADBEEF", Algorithm::SHA256).expect("lesspass");

        // More than 32 bytes to use sha512
        let secret = b"12345678901234567890123456789012345678901234567890";

        let encrypted = master
            .secret_hotp("example.com", "test@example.com", secret)
            .expect("encrypted otp");
        assert_eq!(encrypted.len(), 64);
        let decrypted = master
            .secret_hotp("example.com", "test@example.com", &encrypted)
            .expect("decrypted otp");
        assert_eq!(secret.to_vec(), decrypted);
    }

    #[test]
    fn wrong_otp_secret_length() {
        let master = LessPass::new("DEADBEEF", Algorithm::SHA256).expect("lesspass");

        // no secret, so error
        {
            let secret = b"";
            let encrypted = master.secret_hotp("example.com", "test@example.com", secret);
            assert!(encrypted.is_err());
            assert_eq!(
                encrypted.err().expect("error"),
                LessPassError::InvalidLength
            );
        }

        // more than 64 bytes
        {
            let secret = b"12345678901234567890123456789012345678901234567890123456789012345";
            let encrypted = master.secret_hotp("example.com", "test@example.com", secret);
            assert!(encrypted.is_err());
            assert_eq!(
                encrypted.err().expect("error"),
                LessPassError::InvalidLength
            );
        }
    }
}
