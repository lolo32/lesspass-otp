use crate::charset::{CharacterSet, LowerCase, Numbers, Symbols, UpperCase};
use crate::Algorithm;

/// Settings to derive a new password.
///
/// This is some common settings used to derive a new password.
///
/// # Examples
/// ```
/// use lesspass_otp::Settings;
/// use lesspass_otp::charset::{UpperCase, LowerCase, Symbols, Numbers};
///
/// // Create for a new password of 20 characters length, lower and uppercase characters and numbers
/// let settings = Settings::new(20, LowerCase::Using, UpperCase::Using, Numbers::Using, Symbols::NotUsing);
/// ```
#[derive(Debug, Clone)]
pub struct Settings {
    iterations: Option<u32>,
    pass_len: u8,
    char_set: CharacterSet,
    algorithm: Option<Algorithm>,
}

#[allow(clippy::fn_params_excessive_bools)]
impl Settings {
    /// Instantiate a new [`Settings`], specifying the characters type and password length.
    #[must_use]
    pub fn new(
        pass_len: u8,
        lower: LowerCase,
        upper: UpperCase,
        num: Numbers,
        sym: Symbols,
    ) -> Self {
        Self {
            pass_len,
            char_set: CharacterSet::new(lower, upper, num, sym),
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
    /// use lesspass_otp::charset::{UpperCase, LowerCase, Symbols, Numbers};
    ///
    /// // Create for a new password of 20 characters length, lower and uppercase characters and numbers
    /// let mut settings = Settings::new(20, LowerCase::Using, UpperCase::Using, Numbers::Using, Symbols::NotUsing);
    /// settings.set_iterations(20_000);
    /// ```
    pub fn set_iterations(&mut self, iterations: u32) {
        self.iterations = Some(iterations);
    }

    /// Get number of iterations configured, or default value.
    #[must_use]
    pub fn get_iterations(&self) -> u32 {
        self.iterations.unwrap_or_else(|| 100_000)
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
    /// use lesspass_otp::charset::{UpperCase, LowerCase, Symbols, Numbers};
    ///
    /// // Create for a new password of 20 characters length, lower and uppercase characters and numbers
    /// let mut settings = Settings::new(20, LowerCase::Using, UpperCase::Using, Numbers::Using, Symbols::NotUsing);
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
            char_set: CharacterSet::new(
                LowerCase::Using,
                UpperCase::Using,
                Numbers::Using,
                Symbols::Using,
            ),
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
        use crate::charset::Set;

        // Note: do not change the serialization format, or it may break
        // forward and backward compatibility of serialized data!
        let serials = self.get_characterset().get_serials();
        let mut serials_tuple = (false, false, false, false);
        for serial in serials {
            match serial {
                Set::Lowercase => serials_tuple.0 = true,
                Set::Uppercase => serials_tuple.1 = true,
                Set::Numbers => serials_tuple.2 = true,
                Set::Symbols => serials_tuple.3 = true,
            }
        }
        (
            self.iterations,
            self.pass_len,
            self.algorithm,
            serials_tuple,
        )
            .serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Settings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        type SerdeSetting = (Option<u32>, u8, Option<Algorithm>, (bool, bool, bool, bool));
        let (iterations, pass_len, algorithm, serials): SerdeSetting =
            serde::Deserialize::deserialize(deserializer)?;

        let lower = if serials.0 {
            LowerCase::Using
        } else {
            LowerCase::NotUsing
        };
        let upper = if serials.1 {
            UpperCase::Using
        } else {
            UpperCase::NotUsing
        };
        let num = if serials.2 {
            Numbers::Using
        } else {
            Numbers::NotUsing
        };
        let sym = if serials.3 {
            Symbols::Using
        } else {
            Symbols::NotUsing
        };

        let mut settings = Self::new(pass_len, lower, upper, num, sym);
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
        let mut settings = Settings::new(
            16,
            LowerCase::NotUsing,
            UpperCase::NotUsing,
            Numbers::NotUsing,
            Symbols::NotUsing,
        );
        assert_eq!(settings.get_iterations(), 100_000);
        settings.set_iterations(9_999);
        assert_eq!(settings.get_iterations(), 9_999);
    }

    #[test]
    fn create_with_default() {
        let settings: Settings = Default::default();
        let charset = CharacterSet::new(
            LowerCase::Using,
            UpperCase::Using,
            Numbers::Using,
            Symbols::Using,
        );
        assert_eq!(settings.get_iterations(), 100_000);
        assert_eq!(settings.get_password_len(), 16);
        assert_eq!(settings.get_characterset(), &charset);
        assert!(settings.get_algorithm().is_none());
    }

    #[test]
    fn store_settings_in_creation() {
        let settings = Settings::new(
            29,
            LowerCase::NotUsing,
            UpperCase::Using,
            Numbers::NotUsing,
            Symbols::Using,
        );
        let charset = CharacterSet::new(
            LowerCase::NotUsing,
            UpperCase::Using,
            Numbers::NotUsing,
            Symbols::Using,
        );
        assert_eq!(settings.get_iterations(), 100_000);
        assert_eq!(settings.get_password_len(), 29);
        assert_eq!(settings.get_characterset(), &charset);
        assert!(settings.get_algorithm().is_none());
    }
}
