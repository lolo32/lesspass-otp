use seed::prelude::{ElRef, LocalStorage, WebStorage};
use ulid::Ulid;

use lesspass_otp::{Algorithm, CharacterSet, Fingerprint, LessPass, Settings};

use crate::{
    credential::Credential,
    credentials::Credentials,
    otp::{Otp, OtpSpecialisation, OtpType},
    Page, STORAGE_KEY,
};

// ------ ------
//     Model
// ------ ------

/// `Model` describes our app state.
#[derive(Debug)]
pub struct Model {
    /// List of references
    pub(crate) refs: Refs,
    /// Main encryption/decryption and password generation
    pub(crate) lesspass: Option<LessPass>,
    /// Fingerprint of the master password
    pub(crate) master_fingerprint: Fingerprint,
    /// List of the identifications and OTP
    pub(crate) credentials: Credentials,
    /// Search pattern to filter the keyring
    pub(crate) search_pattern: String,
    /// Page to display
    pub(crate) page: Page,
    /// Flash message to display, depending on the situation
    pub(crate) info: Option<String>,

    pub(crate) otp: Option<Otp>,
    /// Password to display on the credential detail page
    pub(crate) password: Option<String>,
    /// Is the password must be displayed
    pub(crate) password_displayed: bool,
    /// Credential data to use for modification
    pub(crate) credential: Option<Credential>,
}

impl Model {
    /// Save the credential list in the LocalStorage
    pub fn save(&self) {
        LocalStorage::insert(STORAGE_KEY, &self.credentials)
            .expect("save credentials to LocalStorage");
    }

    // TODO: Remove
    pub fn add_mock_data(mut self) -> Self {
        if self.credentials.is_empty() {
            self.credentials.push(Credential {
                id: Ulid::new(),
                site: "facebook.com".to_owned(),
                login: "test@example.com".to_owned(),
                counter: 0,
                settings: Settings::new(32, CharacterSet::LowercaseUppercaseNumbers),
                otp: OtpType::None,
                //logo: "https://upload.wikimedia.org/wikipedia/commons/thumb/8/89/Facebook_Logo_(2019).svg/1200px-Facebook_Logo_(2019).svg.png".to_owned(),
                logo_url: "https://cdn.freebiesupply.com/logos/large/2x/facebook-logo-2019.png"
                    .to_owned(),
                logo_data: vec![],
                password: None,
            });
            self.credentials.push(Credential {
                id: Ulid::new(),
                site: "example.com".to_owned(),
                login: "spam_10_000@example.com".to_owned(),
                counter: 42,
                settings: {
                    let mut settings = Settings::new(70, CharacterSet::LowercaseNumbers);
                    settings.set_iterations(10_000);
                    settings
                },
                otp: OtpType::Totp(
                    OtpSpecialisation {
                        secret_clear: "JV4VGZLDOJSXI".to_owned(),
                        secret_encoded: vec![],
                        digits: 6,
                        algorithm: Algorithm::SHA1,
                        period: 30,
                    },
                    0,
                ),
                logo_url: Default::default(),
                logo_data: vec![],
                password: None,
            });
            self.credentials.push(Credential {
                id: Ulid::new(),
                site: "facebook.com".to_owned(),
                login: "test@example.com".to_owned(),
                counter: 0,
                settings: Default::default(),
                otp: OtpType::None,
                //logo: "https://upload.wikimedia.org/wikipedia/commons/thumb/8/89/Facebook_Logo_(2019).svg/1200px-Facebook_Logo_(2019).svg.png".to_owned(),
                logo_url: "https://cdn.freebiesupply.com/logos/large/2x/facebook-logo-2019.png"
                    .to_owned(),
                logo_data: vec![],
                password: None,
            });
            self.credentials.push(Credential {
                id: Ulid::new(),
                site: "example.com".to_owned(),
                login: "spam@example.com".to_owned(),
                counter: 42,
                settings: Settings::new(30, CharacterSet::LowercaseNumbers),
                otp: OtpType::Totp(
                    OtpSpecialisation {
                        secret_clear: "JV4VGZLDOJSXI".to_owned(),
                        secret_encoded: vec![],
                        digits: 6,
                        algorithm: Algorithm::SHA1,
                        period: 30,
                    },
                    0,
                ),
                logo_url: Default::default(),
                logo_data: vec![],
                password: None,
            });
        }

        self
    }
}

#[derive(Debug, Default, Clone)]
pub struct Refs {
    pub(crate) master_input: ElRef<web_sys::HtmlInputElement>,

    pub(crate) credential_save: ElRef<web_sys::HtmlButtonElement>,
}
