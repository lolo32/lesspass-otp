use seed::prelude::StreamHandle;

use lesspass_otp::Algorithm;

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub enum OtpType {
    None,
    /// Start timestamp
    Totp(OtpSpecialisation, u64),
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
pub struct OtpSpecialisation {
    #[serde(skip)]
    pub(crate) secret_clear: String,
    pub(crate) secret_encoded: Vec<u8>,
    pub(crate) digits: u8,
    pub(crate) algorithm: Algorithm,
    pub(crate) period: u32,
}

#[derive(Debug)]
pub struct Otp {
    pub(crate) time: i64,
    pub(crate) value: Option<String>,
    pub(crate) stream: StreamHandle,
}
