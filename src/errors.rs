use core::fmt;

use crate::Algorithm;

/// Errors that can be return during password generation.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum LessPassError {
    /// The password is too short.
    ///
    /// The first parameter is the minimum value, the second the asked value.
    PasswordTooShort(u8, u8),

    /// The password is too long for the algorithm
    ///
    /// The first parameter is the minimum value, the second the asked value,
    /// the third is the algorithm.
    PasswordTooLong(u8, u8, Algorithm),

    /// No charset is specified, so impossible to generate any password.
    NoCharsetSelected,

    /// The Algorithm specified is not valid where it is used.
    UnsupportedAlgorithm,

    /// The number of digits for the HOTP or TOTP is not valid.
    InvalidLength,

    /// The provided string is not a valid base32 encoded string
    InvalidBase32,
}

impl fmt::Display for LessPassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PasswordTooShort(min, curr) =>
                f.write_str(format!("Password length cannot be less than {} characters, it's {} length", min, curr).as_str()),
            Self::PasswordTooLong(min, curr, algorithm) =>
                f.write_str(format!("Password length cannot be more than {} characters if algorithm is {}. It's {} length.", min, algorithm, curr).as_str()),
            Self::NoCharsetSelected =>
                f.write_str("No charset selected to generate a password. Please use at least one."),
            Self::UnsupportedAlgorithm =>
                f.write_str("This algorithm is not supported."),
            Self::InvalidLength =>
                f.write_str("The number of digits is not valid."),
            Self::InvalidBase32 =>
                f.write_str("The provided string is not a valid base32 encoded string."),
        }
    }
}
