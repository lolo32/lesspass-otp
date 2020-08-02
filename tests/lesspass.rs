use lesspass_otp::charset::{LowerCase, Numbers, Symbols, UpperCase};
use lesspass_otp::{Algorithm, LessPass, Settings};

#[test]
fn external() {
    let lesspass = LessPass::new("password", Algorithm::SHA256).unwrap();
    let fing = lesspass.get_fingerprint(b"");
    assert_eq!(
        &fing,
        &[
            ("#FFB5DA", "fa-flask"),
            ("#009191", "fa-archive"),
            ("#B5DAFE", "fa-beer")
        ]
    );

    let settings = Settings::new(
        16,
        LowerCase::Using,
        UpperCase::Using,
        Numbers::Using,
        Symbols::NotUsing,
    );
    let pass = lesspass.password("lesspass.com", "contact@lesspass.com", 1, &settings);
    assert_eq!(pass.unwrap(), String::from("OlfK63bmUhqrGODR"));
}

#[test]
fn my_test() {
    let lesspass = LessPass::new("test@lesspass.com", Algorithm::SHA256).unwrap();

    let settings = Settings::new(
        35,
        LowerCase::Using,
        UpperCase::Using,
        Numbers::Using,
        Symbols::Using,
    );
    let pass = lesspass.password("lesspass.com", "test@lesspass.com", 1, &settings);
    assert_eq!(
        pass.unwrap(),
        String::from(r"hj@\ULp3Is6B~^1OzW__kRd?4),-\m&FZ}v")
    );
}

#[test]
fn my_test_sha512() {
    let lesspass = LessPass::new("test@lesspass.com", Algorithm::SHA512).unwrap();

    let settings = Settings::new(
        70,
        LowerCase::Using,
        UpperCase::Using,
        Numbers::Using,
        Symbols::Using,
    );
    // settings.set_algorithm(Algorithm::SHA384);
    let pass = lesspass.password("lesspass.com", "test@lesspass.com", 1, &settings);
    assert_eq!(
        pass.unwrap(),
        String::from(r#"PXBx:oINJ!(%rCfy`V\\?4u$W9nvrI!LwV:ZKOgRLZV{"@<j:9k{~3E3%!&nSh`3e~Gcs_"#)
    );
}
