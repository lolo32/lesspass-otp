use num_bigint::BigUint;

use crate::{algo::Algorithm, hex::to, master::Master};

/// Entropy pool to derive the password
#[derive(Debug, Clone)]
pub struct Entropy(BigUint);

impl Entropy {
    /// Return a salt, combining `site`, `login` and `counter` from strings.
    #[must_use]
    pub fn salt(site: &str, login: &str, counter: u32) -> Vec<u8> {
        Self::salt_byte(site.as_bytes(), login.as_bytes(), &to_hex(counter))
    }
    /// Return a salt, combining `site`, `login` and `counter` from byte array.
    #[must_use]
    pub fn salt_byte(site: &[u8], login: &[u8], counter: &[u8]) -> Vec<u8> {
        [site, login, counter].concat()
    }

    /// Generate the entropy, from the master password, a salt and a number of iterations
    #[must_use]
    pub fn new(algorithm: Algorithm, master: &Master, salt: &[u8], iterations: u32) -> Self {
        Self(BigUint::from_bytes_be(&algorithm.pbkdf2(
            master.bytes(),
            salt,
            iterations,
        )))
    }

    /// long division between entropy and length of pool of chars.
    ///
    /// It gives us quotient and a remainder.
    /// Remainder is always between 0 and length of pool of chars.
    /// We use it as an index in pool of chars for the first letter of our generated password.
    pub fn consume(&mut self, len: &BigUint) -> usize {
        use num_integer::Integer;
        use num_traits::ToPrimitive;

        let (quot, rem) = self.0.div_rem(len);
        self.0 = quot;

        rem.to_u64().expect("u64") as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference() {
        let master = Master::new("tHis is a g00d! password", Algorithm::SHA256).expect("lesspass");
        let salt = Entropy::salt("lesspass.com", "\u{2665}", 1);
        let e = Entropy::new(Algorithm::SHA256, &master, &salt, 1);
        assert_eq!(
            e.0,
            BigUint::parse_bytes(
                b"e99e20abab609cc4564ef137acb540de20d9b92dcc5cda58f78ba431444ef2da",
                16,
            )
            .expect("biguint")
        );
    }

    #[test]
    fn another_reference_vector() {
        let master = Master::new("password", Algorithm::SHA256).expect("lesspass");
        let salt = Entropy::salt("example.org", "contact@example.org", 1);
        let e = Entropy::new(Algorithm::SHA256, &master, &salt, 100_000);
        assert_eq!(
            e.0,
            BigUint::parse_bytes(
                b"dc33d431bce2b01182c613382483ccdb0e2f66482cbba5e9d07dab34acc7eb1e",
                16,
            )
            .expect("biguint")
        );
    }
}
