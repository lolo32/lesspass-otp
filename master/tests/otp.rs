use lesspass_otp::{Algorithm, Otp};

#[test]
fn totp() {
    let seed = b"12345678901234567890";
    let t = Otp::new(seed, 8, Some(Algorithm::SHA1), Some(30), Some(0)).unwrap();
    assert_eq!(t.totp_from_ts(20000000000), "65353130");
}

#[test]
fn hotp() {
    let seed = b"12345678901234567890";
    let t = Otp::new(seed, 6, Some(Algorithm::SHA1), None, None).unwrap();
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
