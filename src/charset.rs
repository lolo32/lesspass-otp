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

/// Is lowercase need to be used?
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum LowerCase {
    /// Use Lowercase
    Using,
    /// Do not use Lowercase
    NotUsing,
}

/// Is uppercase need to be used?
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum UpperCase {
    /// Use Uppercase
    Using,
    /// Do not use Uppercase
    NotUsing,
}

/// Is numbers need to be used?
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Numbers {
    /// Use Numbers
    Using,
    /// Do not use Numbers
    NotUsing,
}

/// Is symbols need to be used?
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Symbols {
    /// Use Symbols
    Using,
    /// Do not use Symbols
    NotUsing,
}

/// Configure the characters type to use in the resulting password.
#[derive(Debug, PartialEq)]
pub struct CharacterSet {
    serials: Vec<Set>,
    set: String,
}

#[allow(clippy::fn_params_excessive_bools)]
impl CharacterSet {
    const LOWERCASE: &'static str = "abcdefghijklmnopqrstuvwxyz";
    const UPPERCASE: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const NUMBERS: &'static str = "0123456789";
    const SYMBOLS: &'static str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    /// Specify which characters type to use in the final password.
    #[must_use]
    pub fn new(lower: LowerCase, upper: UpperCase, num: Numbers, sym: Symbols) -> Self {
        let mut serials = Vec::with_capacity(4);
        let mut set = Vec::new();

        if lower == LowerCase::Using {
            serials.push(Set::Lowercase);
            set.push(Self::LOWERCASE);
        }
        if upper == UpperCase::Using {
            serials.push(Set::Uppercase);
            set.push(Self::UPPERCASE);
        }
        if num == Numbers::Using {
            serials.push(Set::Numbers);
            set.push(Self::NUMBERS);
        }
        if sym == Symbols::Using {
            serials.push(Set::Symbols);
            set.push(Self::SYMBOLS);
        }

        Self {
            serials,
            set: set.concat(),
        }
    }

    /// Get the characters lists that could be used.
    #[must_use]
    pub const fn get_chars(&self) -> &String {
        &self.set
    }

    /// Characters list length.
    #[must_use]
    pub fn get_charset_count(&self) -> usize {
        self.serials.len()
    }

    /// Retrieve the list of [`Set`] configured.
    #[must_use]
    pub const fn get_serials(&self) -> &Vec<Set> {
        &self.serials
    }

    /// Retrieve the string corresponding of the `serial` [Set].
    #[must_use]
    pub fn get_serial(&self, serial: Set) -> &'static str {
        match serial {
            Set::Lowercase => Self::LOWERCASE,
            Set::Uppercase => Self::UPPERCASE,
            Set::Numbers => Self::NUMBERS,
            Set::Symbols => Self::SYMBOLS,
        }
    }

    /// Get the characters length of the `serial` [Set].
    #[must_use]
    pub fn serial_len(&self, serial: Set) -> BigUint {
        match serial {
            Set::Lowercase | Set::Uppercase => BigUint::from(Self::LOWERCASE.len()),
            Set::Numbers => BigUint::from(Self::NUMBERS.len()),
            Set::Symbols => BigUint::from(Self::SYMBOLS.len()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_all_chars() {
        let chars = CharacterSet::new(
            LowerCase::Using,
            UpperCase::Using,
            Numbers::Using,
            Symbols::Using,
        );
        assert_eq!(
            chars.get_chars(),
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
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
        let chars = CharacterSet::new(
            LowerCase::Using,
            UpperCase::Using,
            Numbers::Using,
            Symbols::NotUsing,
        );
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
    fn get_lowercase() {
        let chars = CharacterSet::new(
            LowerCase::NotUsing,
            UpperCase::Using,
            Numbers::NotUsing,
            Symbols::NotUsing,
        );
        assert_eq!(chars.get_chars(), "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        assert_eq!(chars.get_chars().len(), 26);

        assert_eq!(chars.get_charset_count(), 1);
        assert_eq!(*chars.get_serials(), vec![Set::Uppercase]);
    }
}
