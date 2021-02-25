use ulid::Ulid;

use crate::{credential::Credential, otp::OtpType};

// `Msg` describes the different events you can modify state with.
#[derive(Clone)]
pub enum Msg {
    Noop,

    /// Master password
    SetMaster,
    CheckMasterFingerprint(String),
    ToggleMasterType,

    ShowCredentialList,
    ShowCredential(Ulid),
    ShowEditCredential(Ulid),
    UpdateModifCredential(Box<Credential>),
    ShowAddCredential,
    CurrentPassord(Ulid, String),
    ShowPassword(bool),

    AddCredential,
    RemoveCredential(Ulid),
    SetLogo,

    AddOtp(Ulid, OtpType),
    RemoveOtp(Ulid),
    SetTotpTime(Ulid, i64),
    ShowOtp(Ulid),

    /// Search data
    SearchCredential(String),

    /// Show information message
    ShowInformation(Option<String>),

    ValidateNewCredentialData,

    /// Downloads and uploads
    Download,
    Upload,
}
