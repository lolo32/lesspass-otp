use crate::{charset::CharacterSet, Algorithm};

/// Settings to derive a new password.
///
/// This is some common settings used to derive a new password.
///
/// # Examples
/// ```
/// use lesspass_otp::Settings;
/// use lesspass_otp::charset::CharacterSet;
///
/// // Create for a new password of 20 characters length, lower and uppercase characters and numbers
/// let settings = Settings::new(20, CharacterSet::LowercaseUppercaseNumbers);
/// ```
#[derive(Debug, Clone, PartialEq, Copy)]
pub struct Settings {
    /// Number of iterations
    iterations: Option<u32>,
    /// Password length
    pass_len: u8,
    /// Characters set to use
    char_set: CharacterSet,
    /// Algorithm to use
    algorithm: Option<Algorithm>,
}

#[allow(clippy::fn_params_excessive_bools)]
impl Settings {
    /// Instantiate a new [`Settings`], specifying the characters type and password length.
    #[must_use]
    pub fn new(pass_len: u8, characters: CharacterSet) -> Self {
        Self {
            pass_len,
            char_set: characters,
            ..Self::default()
        }
    }

    /// Change number of iterations.
    ///
    /// ## Notes
    ///
    /// Doing so, your password will not be compatible anymore with stock Lesspass implementation.
    ///
    /// # Examples
    /// ```
    /// use lesspass_otp::Settings;
    /// use lesspass_otp::charset::CharacterSet;
    ///
    /// // Create for a new password of 20 characters length, lower and uppercase characters and numbers
    /// let mut settings = Settings::new(20, CharacterSet::LowercaseUppercaseNumbers);
    /// settings.set_iterations(20_000);
    /// ```
    pub fn set_iterations(&mut self, iterations: u32) {
        self.iterations = Some(iterations);
    }

    /// Get number of iterations configured, or default value.
    #[must_use]
    pub fn get_iterations(&self) -> u32 {
        self.iterations.unwrap_or(100_000)
    }

    /// Get password length.
    #[must_use]
    pub const fn get_password_len(&self) -> u8 {
        self.pass_len
    }
    /// Change password length.
    pub fn set_password_len(&mut self, length: u8) {
        self.pass_len = length;
    }

    /// Retrieve configured [`CharacterSet`].
    #[must_use]
    pub const fn get_characterset(&self) -> &CharacterSet {
        &self.char_set
    }

    /// Change default [`Algorithm`].
    ///
    /// ## Notes
    ///
    /// Doing so, your password will not be compatible anymore with stock Lesspass implementation.
    ///
    /// # Examples
    /// ```
    /// use lesspass_otp::{Settings, Algorithm};
    /// use lesspass_otp::charset::CharacterSet;
    ///
    /// // Create for a new password of 20 characters length, lower and uppercase characters and numbers
    /// let mut settings = Settings::new(20, CharacterSet::LowercaseUppercaseNumbers);
    /// settings.set_algorithm(Algorithm::SHA512);
    /// ```
    pub fn set_algorithm(&mut self, algorithm: Algorithm) {
        self.algorithm = Some(algorithm);
    }

    /// Get the [`Algorithm`].
    #[must_use]
    pub const fn get_algorithm(&self) -> Option<Algorithm> {
        self.algorithm
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            iterations: None,
            pass_len: 16,
            char_set: CharacterSet::LowercaseUppercaseNumbersSymbols,
            algorithm: None,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Settings {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Note: do not change the serialization format, or it may break
        // forward and backward compatibility of serialized data!

        let characters: u8 = (*self.get_characterset()).into();
        (self.iterations, self.pass_len, self.algorithm, characters).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Settings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::convert::TryFrom;

        /// Description of a serialized password params
        type SerdeSetting = (Option<u32>, u8, Option<Algorithm>, u8);

        let (iterations, pass_len, algorithm, serials): SerdeSetting =
            serde::Deserialize::deserialize(deserializer)?;

        let characters = CharacterSet::try_from(serials).map_err(serde::de::Error::custom)?;

        let mut settings = Self::new(pass_len, characters);
        if let Some(algo) = algorithm {
            settings.set_algorithm(algo);
        }
        if let Some(iter_) = iterations {
            settings.set_iterations(iter_);
        }
        Ok(settings)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_number_of_iterations() {
        let mut settings = Settings::new(16, CharacterSet::Lowercase);
        assert_eq!(settings.get_iterations(), 100_000);
        settings.set_iterations(9_999);
        assert_eq!(settings.get_iterations(), 9_999);
    }

    #[test]
    fn create_with_default() {
        let settings = Settings::default();
        let charset = CharacterSet::LowercaseUppercaseNumbersSymbols;
        assert_eq!(settings.get_iterations(), 100_000);
        assert_eq!(settings.get_password_len(), 16);
        assert_eq!(settings.get_characterset(), &charset);
        assert!(settings.get_algorithm().is_none());
    }

    #[test]
    fn store_settings_in_creation() {
        let settings = Settings::new(29, CharacterSet::UppercaseSymbols);
        let charset = CharacterSet::UppercaseSymbols;
        assert_eq!(settings.get_iterations(), 100_000);
        assert_eq!(settings.get_password_len(), 29);
        assert_eq!(settings.get_characterset(), &charset);
        assert!(settings.get_algorithm().is_none());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde() {
        use serde_test::{assert_tokens, Token};

        let mut settings = Settings::new(42, CharacterSet::LowercaseNumbersSymbols);
        assert_tokens(
            &settings,
            &[
                Token::Tuple { len: 4 },
                Token::None,
                Token::U8(42),
                Token::None,
                Token::U8(13),
                Token::TupleEnd,
            ],
        );

        settings.set_iterations(666);
        settings.set_algorithm(Algorithm::SHA512);
        assert_tokens(
            &settings,
            &[
                Token::Tuple { len: 4 },
                Token::Some,
                Token::U32(666),
                Token::U8(42),
                Token::Some,
                Token::Str("Sha2-512"),
                Token::U8(13),
                Token::TupleEnd,
            ],
        );
    }
}
