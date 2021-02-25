use ulid::Ulid;

use lesspass_otp::Settings;

use crate::OtpType;

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct Credential {
    /// Id of the credential
    pub(crate) id: Ulid,
    /// Website name
    pub(crate) site: String,
    /// Login name
    pub(crate) login: String,
    /// Counter, to change password on site
    pub(crate) counter: u32,
    /// Settings for password making
    pub(crate) settings: Settings,
    /// Type of OTP associated to this website (if any)
    pub(crate) otp: OtpType,
    /// URL of the icon of the site
    pub(crate) logo_url: String,
    /// Array of byte of the logo, saved with credential
    pub(crate) logo_data: Vec<u8>,

    #[serde(skip)]
    /// Already calculated password, no persistent save
    pub(crate) password: Option<String>,
}

impl Default for Credential {
    fn default() -> Self {
        Self {
            id: Ulid::nil(),
            site: "".to_owned(),
            login: "".to_owned(),
            counter: 0,
            settings: Default::default(),
            otp: OtpType::None,
            logo_url: "".to_owned(),
            logo_data: Vec::new(),
            password: None,
        }
    }
}
