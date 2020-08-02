use num_bigint::BigUint;

use crate::algo::Algorithm;
use crate::hex::to_hex;
use crate::master::Master;

#[derive(Debug, Clone)]
pub struct Entropy(BigUint);

impl Entropy {
    /// Return a salt, combining `site`, `login` and `counter` from strings.
    pub(crate) fn salt(site: &str, login: &str, counter: u32) -> Vec<u8> {
        Self::salt_byte(
            site.as_bytes(),
            login.as_bytes(),
            to_hex(counter).as_slice(),
        )
    }
    /// Return a salt, combining `site`, `login` and `counter` from byte array.
    pub(crate) fn salt_byte(site: &[u8], login: &[u8], counter: &[u8]) -> Vec<u8> {
        [site, login, counter].concat()
    }

    /// Generate the entropy, from the master password, a salt and a number of iterations
    pub(crate) fn new(algorithm: Algorithm, master: &Master, salt: &[u8], iterations: u32) -> Self {
        Self(BigUint::from_bytes_be(
            algorithm
                .pbkdf2(master.bytes(), salt, iterations)
                .as_slice(),
        ))
    }

    /// long division between entropy and length of pool of chars.
    ///
    /// It gives us quotient and a remainder.
    /// Remainder is always between 0 and length of pool of chars.
    /// We use it as an index in pool of chars for the first letter of our generated password.
    pub(crate) fn consume(&mut self, len: &BigUint) -> usize {
        use num_integer::Integer;
        use num_traits::ToPrimitive;

        let (quot, rem) = self.0.div_rem(len);
        self.0 = quot;

        match rem.to_u64() {
            Some(rem) => rem as usize,
            None => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference() {
        let master = Master::new("tHis is a g00d! password", Algorithm::SHA256).unwrap();
        let salt = Entropy::salt("lesspass.com", "♥", 1);
        let e = Entropy::new(Algorithm::SHA256, &master, salt.as_slice(), 1);
        assert_eq!(
            e.0,
            BigUint::parse_bytes(
                b"e99e20abab609cc4564ef137acb540de20d9b92dcc5cda58f78ba431444ef2da",
                16,
            )
            .unwrap()
        );
    }

    #[test]
    fn another_reference_vector() {
        let master = Master::new("password", Algorithm::SHA256).unwrap();
        let salt = Entropy::salt("example.org", "contact@example.org", 1);
        let e = Entropy::new(Algorithm::SHA256, &master, salt.as_slice(), 100_000);
        assert_eq!(
            e.0,
            BigUint::parse_bytes(
                b"dc33d431bce2b01182c613382483ccdb0e2f66482cbba5e9d07dab34acc7eb1e",
                16,
            )
            .unwrap()
        );
    }
}
