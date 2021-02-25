use std::convert::TryFrom;

use num_bigint::BigUint;

/// Charset that to be used during password derivation
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Set {
    /// Use Uppercase letters
    Uppercase,

    /// Use Lowercase letters
    Lowercase,

    /// Use numbers
    Numbers,

    /// Use symbols
    Symbols,
}

/// If the charset must be used or not
#[derive(Debug, Copy, Clone)]
pub enum CharUse {
    /// Use it
    Use,
    /// Do not use it
    DontUse,
}

/// Configure the characters type to use in the resulting password.
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum CharacterSet {
    /// Does not use any encoding
    None,

    /// Use Lowercase
    Lowercase,
    /// Use Uppercase
    Uppercase,
    /// Use Numbers
    Numbers,
    /// Use Symbols
    Symbols,

    /// Lower and Upper case
    LowercaseUppercase,
    /// Lowercase and Numbers
    LowercaseNumbers,
    /// Lowercase and Symbols
    LowercaseSymbols,
    /// Uppercase and Numbers
    UppercaseNumbers,
    /// Uppercase and Symbols
    UppercaseSymbols,
    /// Numbers and Symbols
    NumbersSymbols,

    /// Alphanums
    LowercaseUppercaseNumbers,
    /// Alpha and Symbols
    LowercaseUppercaseSymbols,
    /// Lowercase and Numbers and Symbols
    LowercaseNumbersSymbols,
    /// Uppercase and Numbers and Symbols
    UppercaseNumbersSymbols,

    /// All of them
    LowercaseUppercaseNumbersSymbols,
}

impl CharacterSet {
    /// Lowercase characters
    const LOWERCASE: &'static str = "abcdefghijklmnopqrstuvwxyz";
    /// Uppercase characters
    const UPPERCASE: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    /// Numbers
    const NUMBERS: &'static str = "0123456789";
    /// Symbols list
    const SYMBOLS: &'static str = r##"!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"##;

    /// Is the Characters to use must contains some lowercase characters
    #[must_use]
    pub fn is_lower(self) -> bool {
        u8::from(self) & 0b0001 != 0
    }
    /// Set if lowercase must be used
    pub fn set_lower(&mut self, lower: CharUse) -> &mut Self {
        self.set_charset(lower, 0b0001)
    }
    /// Is the Characters to use must contains some uppercase characters
    #[must_use]
    pub fn is_upper(self) -> bool {
        u8::from(self) & 0b0010 != 0
    }
    /// Set if uppercase must be used
    pub fn set_upper(&mut self, upper: CharUse) -> &mut Self {
        self.set_charset(upper, 0b0010)
    }
    /// Is the Characters to use must contains some numbers characters
    #[must_use]
    pub fn is_number(self) -> bool {
        u8::from(self) & 0b0100 != 0
    }
    /// Set if uppercase must be used
    pub fn set_number(&mut self, number: CharUse) -> &mut Self {
        self.set_charset(number, 0b0100)
    }
    /// Is the Characters to use must contains some symbols characters
    #[must_use]
    pub fn is_symbol(self) -> bool {
        u8::from(self) & 0b1000 != 0
    }
    /// Set if uppercase must be used
    pub fn set_symbol(&mut self, symbol: CharUse) -> &mut Self {
        self.set_charset(symbol, 0b1000)
    }

    /// Set the new flag
    fn set_charset(&mut self, to_use: CharUse, charset: u8) -> &mut Self {
        let num = match to_use {
            CharUse::Use => u8::from(*self) | charset,
            CharUse::DontUse => u8::from(*self) & !charset,
        };
        *self = Self::try_from(num).expect("modified charset");
        self
    }

    /// Get the characters lists that could be used.
    #[must_use]
    pub fn get_chars(self) -> String {
        match self {
            Self::None => String::new(),
            Self::Lowercase => Self::LOWERCASE.to_owned(),
            Self::Uppercase => Self::UPPERCASE.to_owned(),
            Self::Numbers => Self::NUMBERS.to_owned(),
            Self::Symbols => Self::SYMBOLS.to_owned(),
            Self::LowercaseUppercase => Self::LOWERCASE.to_owned() + Self::UPPERCASE,
            Self::LowercaseNumbers => Self::LOWERCASE.to_owned() + Self::NUMBERS,
            Self::LowercaseSymbols => Self::LOWERCASE.to_owned() + Self::SYMBOLS,
            Self::UppercaseNumbers => Self::UPPERCASE.to_owned() + Self::NUMBERS,
            Self::UppercaseSymbols => Self::UPPERCASE.to_owned() + Self::SYMBOLS,
            Self::NumbersSymbols => Self::NUMBERS.to_owned() + Self::SYMBOLS,
            Self::LowercaseUppercaseNumbers => {
                Self::LOWERCASE.to_owned() + Self::UPPERCASE + Self::NUMBERS
            }
            Self::LowercaseUppercaseSymbols => {
                Self::LOWERCASE.to_owned() + Self::UPPERCASE + Self::SYMBOLS
            }
            Self::LowercaseNumbersSymbols => {
                Self::LOWERCASE.to_owned() + Self::NUMBERS + Self::SYMBOLS
            }
            Self::UppercaseNumbersSymbols => {
                Self::UPPERCASE.to_owned() + Self::NUMBERS + Self::SYMBOLS
            }
            Self::LowercaseUppercaseNumbersSymbols => {
                Self::LOWERCASE.to_owned() + Self::UPPERCASE + Self::NUMBERS + Self::SYMBOLS
            }
        }
    }

    /// Characters list length.
    #[must_use]
    pub const fn get_charset_count(self) -> usize {
        match self {
            Self::None => 0,
            Self::Lowercase | Self::Uppercase | Self::Numbers | Self::Symbols => 1,
            Self::LowercaseUppercase
            | Self::LowercaseNumbers
            | Self::LowercaseSymbols
            | Self::UppercaseNumbers
            | Self::UppercaseSymbols
            | Self::NumbersSymbols => 2,
            Self::LowercaseUppercaseNumbers
            | Self::LowercaseUppercaseSymbols
            | Self::LowercaseNumbersSymbols
            | Self::UppercaseNumbersSymbols => 3,
            Self::LowercaseUppercaseNumbersSymbols => 4,
        }
    }

    /// Retrieve the list of [`Set`] configured.
    #[must_use]
    pub const fn get_serials(self) -> &'static [Set] {
        match self {
            Self::None => &[],
            Self::Lowercase => &[Set::Lowercase],
            Self::Uppercase => &[Set::Uppercase],
            Self::Numbers => &[Set::Numbers],
            Self::Symbols => &[Set::Symbols],
            Self::LowercaseUppercase => &[Set::Lowercase, Set::Uppercase],
            Self::LowercaseNumbers => &[Set::Lowercase, Set::Numbers],
            Self::LowercaseSymbols => &[Set::Lowercase, Set::Symbols],
            Self::UppercaseNumbers => &[Set::Uppercase, Set::Numbers],
            Self::UppercaseSymbols => &[Set::Uppercase, Set::Symbols],
            Self::NumbersSymbols => &[Set::Numbers, Set::Symbols],
            Self::LowercaseUppercaseNumbers => &[Set::Lowercase, Set::Uppercase, Set::Numbers],
            Self::LowercaseUppercaseSymbols => &[Set::Lowercase, Set::Uppercase, Set::Symbols],
            Self::LowercaseNumbersSymbols => &[Set::Lowercase, Set::Numbers, Set::Symbols],
            Self::UppercaseNumbersSymbols => &[Set::Uppercase, Set::Numbers, Set::Symbols],
            Self::LowercaseUppercaseNumbersSymbols => {
                &[Set::Lowercase, Set::Uppercase, Set::Numbers, Set::Symbols]
            }
        }
    }

    /// Retrieve the string corresponding of the `serial` [Set].
    #[must_use]
    pub const fn get_serial(serial: Set) -> &'static str {
        match serial {
            Set::Lowercase => Self::LOWERCASE,
            Set::Uppercase => Self::UPPERCASE,
            Set::Numbers => Self::NUMBERS,
            Set::Symbols => Self::SYMBOLS,
        }
    }

    /// Get the characters length of the `serial` [Set].
    #[must_use]
    pub fn serial_len(serial: Set) -> BigUint {
        match serial {
            Set::Lowercase | Set::Uppercase => BigUint::from(Self::LOWERCASE.len()),
            Set::Numbers => BigUint::from(Self::NUMBERS.len()),
            Set::Symbols => BigUint::from(Self::SYMBOLS.len()),
        }
    }
}

impl TryFrom<u8> for CharacterSet {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b0000 => Ok(Self::None),
            0b0001 => Ok(Self::Lowercase),
            0b0010 => Ok(Self::Uppercase),
            0b0011 => Ok(Self::LowercaseUppercase),
            0b0100 => Ok(Self::Numbers),
            0b0101 => Ok(Self::LowercaseNumbers),
            0b0110 => Ok(Self::UppercaseNumbers),
            0b0111 => Ok(Self::LowercaseUppercaseNumbers),
            0b1000 => Ok(Self::Symbols),
            0b1001 => Ok(Self::LowercaseSymbols),
            0b1010 => Ok(Self::UppercaseSymbols),
            0b1011 => Ok(Self::LowercaseUppercaseSymbols),
            0b1100 => Ok(Self::NumbersSymbols),
            0b1101 => Ok(Self::LowercaseNumbersSymbols),
            0b1110 => Ok(Self::UppercaseNumbersSymbols),
            0b1111 => Ok(Self::LowercaseUppercaseNumbersSymbols),

            _ => Err(format!("Unsupported value: {}", value)),
        }
    }
}
impl From<CharacterSet> for u8 {
    fn from(value: CharacterSet) -> Self {
        match value {
            CharacterSet::None => 0b0000,
            CharacterSet::Lowercase => 0b0001,
            CharacterSet::Uppercase => 0b0010,
            CharacterSet::LowercaseUppercase => 0b0011,
            CharacterSet::Numbers => 0b0100,
            CharacterSet::LowercaseNumbers => 0b0101,
            CharacterSet::UppercaseNumbers => 0b0110,
            CharacterSet::LowercaseUppercaseNumbers => 0b0111,
            CharacterSet::Symbols => 0b1000,
            CharacterSet::LowercaseSymbols => 0b1001,
            CharacterSet::UppercaseSymbols => 0b1010,
            CharacterSet::LowercaseUppercaseSymbols => 0b1011,
            CharacterSet::NumbersSymbols => 0b1100,
            CharacterSet::LowercaseNumbersSymbols => 0b1101,
            CharacterSet::UppercaseNumbersSymbols => 0b1110,
            CharacterSet::LowercaseUppercaseNumbersSymbols => 0b1111,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_lower() {
        let mut set = CharacterSet::LowercaseUppercaseNumbersSymbols;
        assert_eq!(set.is_lower(), true);

        let _ = set.set_lower(CharUse::DontUse);
        assert_eq!(set.is_lower(), false);
        assert_eq!(set, CharacterSet::UppercaseNumbersSymbols);

        let _ = set.set_lower(CharUse::Use);
        assert_eq!(set.is_lower(), true);
        assert_eq!(set, CharacterSet::LowercaseUppercaseNumbersSymbols);

        let _ = set.set_lower(CharUse::Use);
        assert_eq!(set.is_lower(), true);
        assert_eq!(set, CharacterSet::LowercaseUppercaseNumbersSymbols);
    }

    #[test]
    fn toggle_upper() {
        let mut set = CharacterSet::LowercaseUppercaseNumbersSymbols;
        assert_eq!(set.is_upper(), true);

        let _ = set.set_upper(CharUse::DontUse);
        assert_eq!(set.is_upper(), false);
        assert_eq!(set, CharacterSet::LowercaseNumbersSymbols);

        let _ = set.set_upper(CharUse::Use);
        assert_eq!(set.is_upper(), true);
        assert_eq!(set, CharacterSet::LowercaseUppercaseNumbersSymbols);

        let _ = set.set_upper(CharUse::Use);
        assert_eq!(set.is_upper(), true);
        assert_eq!(set, CharacterSet::LowercaseUppercaseNumbersSymbols);
    }

    #[test]
    fn toggle_number() {
        let mut set = CharacterSet::LowercaseUppercaseNumbersSymbols;
        assert_eq!(set.is_number(), true);

        let _ = set.set_number(CharUse::DontUse);
        assert_eq!(set.is_number(), false);
        assert_eq!(set, CharacterSet::LowercaseUppercaseSymbols);

        let _ = set.set_number(CharUse::Use);
        assert_eq!(set.is_number(), true);
        assert_eq!(set, CharacterSet::LowercaseUppercaseNumbersSymbols);

        let _ = set.set_number(CharUse::Use);
        assert_eq!(set.is_number(), true);
        assert_eq!(set, CharacterSet::LowercaseUppercaseNumbersSymbols);
    }

    #[test]
    fn toggle_symbol() {
        let mut set = CharacterSet::LowercaseUppercaseNumbersSymbols;
        assert_eq!(set.is_symbol(), true);

        let _ = set.set_symbol(CharUse::DontUse);
        assert_eq!(set.is_symbol(), false);
        assert_eq!(set, CharacterSet::LowercaseUppercaseNumbers);

        let _ = set.set_symbol(CharUse::Use);
        assert_eq!(set.is_symbol(), true);
        assert_eq!(set, CharacterSet::LowercaseUppercaseNumbersSymbols);

        let _ = set.set_symbol(CharUse::Use);
        assert_eq!(set.is_symbol(), true);
        assert_eq!(set, CharacterSet::LowercaseUppercaseNumbersSymbols);
    }

    #[test]
    fn toggle_all() {
        let mut set = CharacterSet::None;
        assert_eq!(set, CharacterSet::None);
        let _ = set
            .set_upper(CharUse::Use)
            .set_symbol(CharUse::Use)
            .set_number(CharUse::Use)
            .set_lower(CharUse::Use);
        assert_eq!(set, CharacterSet::LowercaseUppercaseNumbersSymbols);
    }

    #[test]
    fn get_all_chars() {
        let chars = CharacterSet::LowercaseUppercaseNumbersSymbols;
        assert_eq!(
            chars.get_chars(),
            r##"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"##
        );
        assert_eq!(chars.get_chars().len(), 26 * 2 + 10 + 32);

        assert_eq!(chars.get_charset_count(), 4);
        assert_eq!(
            *chars.get_serials(),
            vec![Set::Lowercase, Set::Uppercase, Set::Numbers, Set::Symbols]
        );
    }

    #[test]
    fn get_alphanum() {
        let chars = CharacterSet::LowercaseUppercaseNumbers;
        assert_eq!(
            chars.get_chars(),
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        );
        assert_eq!(chars.get_chars().len(), 26 * 2 + 10);

        assert_eq!(chars.get_charset_count(), 3);
        assert_eq!(
            *chars.get_serials(),
            vec![Set::Lowercase, Set::Uppercase, Set::Numbers]
        );
    }

    #[test]
    fn get_uppercase() {
        let chars = CharacterSet::Uppercase;
        assert_eq!(chars.get_chars(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert_eq!(chars.get_chars().len(), 26);

        assert_eq!(chars.get_charset_count(), 1);
        assert_eq!(*chars.get_serials(), vec![Set::Uppercase]);
    }
}
