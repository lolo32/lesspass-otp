//#![deny(missing_docs)]
#![deny(missing_copy_implementations)]
#![deny(missing_debug_implementations)]
#![deny(trivial_numeric_casts)]
//#![deny(unreachable_pub)]
//#![deny(unsafe_code)]
#![deny(unused_extern_crates)]
#![deny(unused_qualifications)]
#![allow(clippy::wildcard_imports)]
// TODO: Remove
#![allow(dead_code, unused_variables)]

use enclose::enc;
use seed::{prelude::*, *};
use ulid::Ulid;

use lesspass_otp::{
    charset::{LowerCase, Numbers, Set, Symbols, UpperCase},
    Algorithm, Fingerprint, LessPass, Settings,
};

use crate::ui::*;
use crate::utils::*;

mod time;
mod ui;
mod utils;

const ALGORITHM: Algorithm = Algorithm::SHA256;
const STORAGE_KEY: &str = "lesspass-seed";

const ENTER_KEY: &str = "Enter";

// ------ ------
//     Init
// ------ ------

// `init` describes what should happen when your app started.
fn init(_url: Url, _orders: &mut impl Orders<Msg>) -> Model {
    Model {
        refs: Default::default(),
        lesspass: None,
        master_fingerprint: LessPass::new("", Algorithm::SHA256)
            .unwrap()
            .get_fingerprint(b""),
        credentials: LocalStorage::get(STORAGE_KEY).unwrap_or_default(),
        search_pattern: "".to_string(),
        page: Page::None,
        info: Default::default(),
        otp: None,
        password: None,
        credential: None,
    }
    .add_mock_data()
}

// ------ ------
//     Model
// ------ ------

// `Model` describes our app state.
#[derive(Debug)]
struct Model {
    // List of references
    refs: Refs,
    // Main encryption/decryption and password generation
    lesspass: Option<LessPass>,
    // Fingerprint of the master password
    master_fingerprint: Fingerprint,
    // List of the identifications and OTP
    credentials: Vec<Credential>,
    // Search pattern to filter the keyring
    search_pattern: String,
    // Page to display
    page: Page,
    // Flash message to display, depending on the situation
    info: Option<String>,

    otp: Option<Otp>,
    // Password to display on the credential detail page
    password: Option<String>,
    // Credential data to use for modification
    credential: Option<Credential>,
}

// TODO: Remove
impl Model {
    fn add_mock_data(mut self) -> Self {
        let (id_a, id_b, id_c, id_d) = (Ulid::new(), Ulid::new(), Ulid::new(), Ulid::new());

        self.credentials.push(Credential {
            id: id_a,
            site: "facebook.com".to_string(),
            login: "test@example.com".to_string(),
            counter: 0,
            settings: Default::default(),
            otp: OtpType::None,
            //logo: "https://upload.wikimedia.org/wikipedia/commons/thumb/8/89/Facebook_Logo_(2019).svg/1200px-Facebook_Logo_(2019).svg.png".to_string(),
            logo_url: "https://cdn.freebiesupply.com/logos/large/2x/facebook-logo-2019.png"
                .to_string(),
            logo_data: vec![],
            password: None,
        });
        self.credentials.push(Credential {
            id: id_b,
            site: "example.com".to_string(),
            login: "spam_10_000@example.com".to_string(),
            counter: 42,
            settings: {
                let mut settings = Settings::new(
                    70,
                    LowerCase::Using,
                    UpperCase::NotUsing,
                    Numbers::Using,
                    Symbols::NotUsing,
                );
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
            id: id_c,
            site: "facebook.com".to_string(),
            login: "test@example.com".to_string(),
            counter: 0,
            settings: Default::default(),
            otp: OtpType::None,
            //logo: "https://upload.wikimedia.org/wikipedia/commons/thumb/8/89/Facebook_Logo_(2019).svg/1200px-Facebook_Logo_(2019).svg.png".to_string(),
            logo_url: "https://cdn.freebiesupply.com/logos/large/2x/facebook-logo-2019.png"
                .to_string(),
            logo_data: vec![],
            password: None,
        });
        self.credentials.push(Credential {
            id: id_d,
            site: "example.com".to_string(),
            login: "spam@example.com".to_string(),
            counter: 42,
            settings: Settings::new(
                30,
                LowerCase::Using,
                UpperCase::NotUsing,
                Numbers::Using,
                Symbols::NotUsing,
            ),
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

        self
    }
}

#[derive(Debug, Default, Clone)]
struct Refs {
    master_input: ElRef<web_sys::HtmlInputElement>,

    credential_save: ElRef<web_sys::HtmlButtonElement>,
}

#[derive(Debug)]
enum Page {
    None,
    Credential(Ulid),
    AddCredential,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct Credential {
    /// Id of the credential
    id: Ulid,
    /// Website name
    site: String,
    /// Login name
    login: String,
    /// Counter, to change password on site
    counter: u32,
    /// Settings for password making
    settings: Settings,
    /// Type of OTP associated to this website (if any)
    otp: OtpType,
    /// URL of the icon of the site
    logo_url: String,
    /// Array of byte of the logo, saved with credential
    logo_data: Vec<u8>,

    #[serde(skip)]
    /// Already calculated password, no persistent save
    password: Option<String>,
}

impl Default for Credential {
    fn default() -> Self {
        Self {
            id: Ulid::nil(),
            site: "".to_string(),
            login: "".to_string(),
            counter: 0,
            settings: Default::default(),
            otp: OtpType::None,
            logo_url: "".to_string(),
            logo_data: vec![],
            password: None,
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
enum OtpType {
    None,
    /// Start timestamp
    Totp(OtpSpecialisation, u64),
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct OtpSpecialisation {
    #[serde(skip)]
    secret_clear: String,
    secret_encoded: Vec<u8>,
    digits: u8,
    algorithm: Algorithm,
    period: u32,
}

#[derive(Debug, Default)]
struct Info {
    message: Option<String>,
    stream: Option<StreamHandle>,
}

#[derive(Debug)]
struct Otp {
    time: i64,
    value: Option<String>,
    stream: StreamHandle,
}

// ------ ------
//    Update
// ------ ------

// `Msg` describes the different events you can modify state with.
#[derive(Clone)]
enum Msg {
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
    ShowPassword(Ulid, String),

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

// `update` describes how to handle each `Msg`.
fn update(msg: Msg, model: &mut Model, orders: &mut impl Orders<Msg>) {
    match msg {
        Msg::Noop => {
            log!("Noop");
        }

        Msg::ToggleMasterType => {
            log!("ToggleMasterType");
            let master = model.refs.master_input.get().expect("get master element");
            match master.type_().as_str() {
                "password" => master.set_type("text"),
                _ => master.set_type("password"),
            }
        }

        // ---------- Master password ----------
        Msg::SetMaster => {
            log!("SetMaster");
            let master = model
                .refs
                .master_input
                .get()
                .expect("get master element")
                .value();
            model.lesspass = LessPass::new(master.as_str(), ALGORITHM).ok();
            orders.send_msg(Msg::ShowCredentialList);
        }
        Msg::CheckMasterFingerprint(master_password) => {
            log!("CheckMasterFingerprint", master_password);
            if let Ok(lesspass) = LessPass::new(master_password.as_str(), ALGORITHM) {
                model.master_fingerprint = lesspass.get_fingerprint(b"");
            }
        }

        // ---------- Credentials ----------
        Msg::ShowCredentialList => {
            log!("ShowCredentialList");
            model.page = Page::None;
            model.otp = None;
            model.credential = None;
        }
        Msg::ShowCredential(id) => {
            log!("ShowCredential", id);
            model.page = Page::Credential(id);
            model.password = None;

            if let Some((index, credential)) = search_credential(model.credentials.as_slice(), id) {
                // Display password
                match credential.password.as_ref() {
                    None => {
                        let id = credential.id;
                        let master = model.lesspass.as_ref().unwrap().clone();
                        let credential = credential.clone();

                        orders.perform_cmd(cmds::timeout(100, move || {
                            log!("Stream");
                            let password = master.password_with_algorithm_from_length(
                                credential.site.as_str(),
                                credential.login.as_str(),
                                credential.counter,
                                &credential.settings,
                            );
                            log!(password);
                            Msg::ShowPassword(id, password.unwrap())
                        }));
                    }
                    Some(password) => {
                        orders.send_msg(Msg::ShowPassword(credential.id, password.clone()));
                    }
                }
                // Display TOTP
                match &credential.otp {
                    OtpType::Totp(settings, time_start) => {
                        let id = id;
                        let period = settings.period;
                        let now =
                            move || i64::from(period) - (time::now() / 1000) % i64::from(period);
                        model.otp = Some(Otp {
                            time: now(),
                            value: None,
                            stream: {
                                orders.stream_with_handle(streams::interval(250, move || {
                                    Msg::SetTotpTime(id, now())
                                }))
                            },
                        });
                    }
                    OtpType::None => {}
                }
            }
        }
        Msg::ShowEditCredential(id) => {
            log!("ShowEditCredential", id);
            if let Some((index, credential)) = search_credential(&model.credentials, id) {
                let mut credential = credential.clone();
                credential.password = None;
                model.credential = Some(credential);

                model.page = Page::AddCredential;
            }
        }
        Msg::UpdateModifCredential(box_credential) => {
            log!("UpdateModifCredential", box_credential);
            model.credential = Some(*box_credential);
            orders.send_msg(Msg::ValidateNewCredentialData);
        }
        Msg::ShowAddCredential => {
            log!("ShowAddCredential");
            model.credential = Some(Default::default());
            model.page = Page::AddCredential;
        }
        Msg::ShowPassword(id, password) => {
            model.password = Some(password.clone());
            if let Some((index, _)) = search_credential(&model.credentials, id) {
                model.credentials[index].password = Some(password);
            }
        }

        Msg::AddCredential => {
            use core::cmp::Ordering;

            log!("AddCredential");
            let credential_ref = model.credential.as_ref().expect("getting credential");
            let mut credential = credential_ref.clone();

            let id = if credential.id.is_nil() {
                // If it's a new, generate a new id
                Ulid::nil()
            } else {
                credential.id
            };

            // OTP Part
            match &credential_ref.otp {
                OtpType::None => {}
                OtpType::Totp(params, ts) => {}
            }

            if let Some((index, _)) = search_credential(&model.credentials, credential.id) {
                // Modification
                model.credentials[index] = credential;
            } else {
                // New credential
                let mut index = model.credentials.len();
                // Insert in ordering, based on site name and login information
                for (i, cred) in model.credentials.iter().enumerate() {
                    match cred.site.cmp(&credential.site) {
                        // Lower website name, so adding maybe to the next iteration
                        Ordering::Less => {}
                        // Same website name, try to compare the login name
                        Ordering::Equal if cred.login.cmp(&credential.login) == Ordering::Less => {}
                        _ => {
                            index = i;
                            break;
                        }
                    }
                }

                credential.id = id;

                if index > model.credentials.len() {
                    // If index is at the last position, push the element
                    model.credentials.push(credential);
                } else {
                    // or insert it at the `index` position
                    model.credentials.insert(index, credential);
                }
            }

            save_storage(model);

            // Show the saved credential
            orders.send_msg(Msg::ShowCredential(id));
        }
        Msg::RemoveCredential(id) => {
            log!("RemoveCredential", id);
            if let Some((index, _)) = search_credential(&model.credentials, id) {
                model.credentials.remove(index);
                save_storage(model);
            }
            orders.send_msg(Msg::ShowCredentialList);
        }
        Msg::SetLogo => {
            log!("SetLogo");
            save_storage(model);
        }

        // ---------- Otp ----------
        Msg::AddOtp(id, otp) => {
            log!("AddOtp", id, otp);
            save_storage(model);
        }
        Msg::RemoveOtp(id) => {
            log!("RemoveOtp", id);
            save_storage(model);
        }
        Msg::SetTotpTime(id, t) => {
            // log!("SetTotpTime", t);
            if model.otp.is_some() {
                let otp = model.otp.as_mut().unwrap();
                if t == otp.time {
                    // Same time, so no new rendering
                    orders.skip();
                    return;
                }
                if otp.value.is_some() && t > otp.time {
                    // Hide the code after it's expiration
                    otp.value = None;
                    // Show new valid code after it's expiration
                    //orders.send_msg(Msg::ShowOtp(id));
                }

                otp.time = t;
            } else {
                orders.skip();
            }
        }
        Msg::ShowOtp(id) => {
            log!("ShowOtp", id);
            if let Some((index, credential)) = search_credential(model.credentials.as_slice(), id) {
                if let OtpType::Totp(settings, timestamp) = &credential.otp {
                    let otp = lesspass_otp::Otp::new(
                        &lesspass_otp::decode_base32(&settings.secret_clear).unwrap(),
                        settings.digits,
                        Some(settings.algorithm),
                        Some(settings.period),
                        None,
                    )
                    .unwrap();
                    model.otp.as_mut().unwrap().value =
                        Some(otp.totp_from_ts((time::now() / 1000) as u64));
                }
            }
        }

        // ---------- Search ----------
        Msg::SearchCredential(search) => {
            log!("SearchCredential", search);
            model.search_pattern = search;
        }

        // ---------- Information message ----------
        Msg::ShowInformation(message) => {
            log!("ShowInformation", message);

            if message.is_some() {
                orders.perform_cmd(cmds::timeout(900, || Msg::ShowInformation(None)));
            }
            model.info = message;
        }

        Msg::ValidateNewCredentialData => {
            log!("ValidateNewCredentialData");
            orders.skip();

            if let Some(credential) = model.credential.as_ref() {
                let disable = |val: bool| {
                    model
                        .refs
                        .credential_save
                        .get()
                        .expect("getting save element")
                        .set_disabled(val);
                };
                let charsets = credential.settings.get_characterset().get_serials();

                if !charsets.contains(&Set::Lowercase)
                    && !charsets.contains(&Set::Uppercase)
                    && !charsets.contains(&Set::Numbers)
                    && !charsets.contains(&Set::Symbols)
                    || credential.site.trim().is_empty()
                    || credential.login.trim().is_empty()
                {
                    disable(true);
                } else {
                    disable(false);
                }
            }
        }

        Msg::Download => {
            log!("Download");
        }
        Msg::Upload => {
            log!("Upload");
        }
    }
}

// ------ ------
//     View
// ------ ------

// `view` describes what to display.
fn view(model: &Model) -> Vec<Node<Msg>> {
    vec![
        // main page
        match model.lesspass {
            None => view_master(model.master_fingerprint, &model.refs.master_input),
            Some(_) => view_credentials(model),
        },
        // Modal dialog
        match &model.page {
            // No modal page
            Page::None => empty!(),

            // Add new credential modal page
            Page::AddCredential => view_add_credential(
                &model.refs,
                model.credential.as_ref().expect("get credential"),
            ),

            // Modify credential modal page
            Page::Credential(id) => {
                if let Some((index, credential)) =
                    search_credential(model.credentials.as_ref(), *id)
                {
                    log!("Page::Credential", id, "credential");
                    view_show_credential(
                        model.lesspass.as_ref().unwrap(),
                        credential,
                        model.info.as_ref(),
                        model.otp.as_ref(),
                        model.password.as_ref(),
                    )
                } else {
                    empty!()
                }
            }
        },
    ]
}

fn view_master(
    master_fingerprint: Fingerprint,
    master_input_ref: &ElRef<web_sys::HtmlInputElement>,
) -> Node<Msg> {
    const MASTER_PASSWORD: &str = "master-password";

    section![
        C!["master"],
        div![
            label![
                attrs! {At::For => MASTER_PASSWORD},
                "Master password: ",
                input![
                    el_ref(master_input_ref),
                    attrs! {
                        At::Id => MASTER_PASSWORD,
                        At::AutoComplete => false,
                        At::Type => "password",
                        At::Placeholder => "Your strong password!!!",
                        At::AutoFocus => true
                    },
                    input_ev(Ev::Input, Msg::CheckMasterFingerprint),
                    keyboard_event(|| Some(Msg::SetMaster))
                ]
            ],
            span![
                C![W3_BUTTON, W3_PADDING_SMALL, W3_MEDIUM],
                attrs! {At::TabIndex => 0, At::Title => "Fingerprint of your password"},
                master_fingerprint
                    .iter()
                    .map(|(color, icon)| {
                        i![fa("w"), C![icon], style! { St::Color => color}, " "]
                    })
                    .collect::<Vec<_>>(),
                mouse_ev(Ev::Click, |_| Msg::ToggleMasterType),
                keyboard_event(|| Some(Msg::ToggleMasterType))
            ],
            button![
                C![W3_BUTTON, W3_BORDER_THEME, W3_THEME_ACTION, W3_HOVER_THEME],
                "Ok",
                mouse_ev(Ev::Click, |_| Msg::SetMaster)
            ]
        ]
    ]
}

fn view_credentials(model: &Model) -> Node<Msg> {
    const SEARCH: &str = "search";

    section![
        C!["credentials"],
        header![
            C![W3_ROW_PADDING, W3_CARD_4, W3_THEME_DARK, "topnav"],
            div![
                C![W3_COL, "s12", W3_PADDING_16],
                label![
                    attrs! {At::For => SEARCH},
                    "Search: ",
                    input![
                        C![W3_ROUND_LARGE, W3_BORDER_0, W3_SHOW_INLINE_BLOCK],
                        attrs! {
                            At::Id => SEARCH,
                            At::Placeholder => "Search in your keyring",
                            At::AutoComplete => false,
                            At::AutoFocus => true,
                            At::Value => model.search_pattern
                        },
                        style! {St::Width => unit!(50, Unit::Percent)},
                        input_ev(Ev::Input, Msg::SearchCredential)
                    ]
                ],
                " ",
                span![
                    fa("user-plus"),
                    C![W3_XLARGE, POINTER],
                    attrs! {At::Title => "Adding new entry", At::TabIndex => 0},
                    mouse_ev(Ev::Click, |_| Msg::ShowAddCredential),
                    keyboard_event(|| Some(Msg::ShowAddCredential))
                ],
                div![
                    C![W3_XLARGE, W3_RIGHT, W3_RIGHT_ALIGN],
                    span![
                        fa("upload"),
                        C![POINTER],
                        attrs! {At::Title => "Upload from disk", At::TabIndex => 0},
                        mouse_ev(Ev::Click, |_| Msg::Upload),
                        keyboard_event(|| Some(Msg::Upload))
                    ],
                    " ",
                    span![
                        fa("download"),
                        C![POINTER],
                        attrs! {At::Title => "Save the keyring to disk",At::TabIndex => 0},
                        mouse_ev(Ev::Click, |_| Msg::Download),
                        keyboard_event(|| Some(Msg::Download))
                    ]
                ]
            ]
        ],
        div![
            C![W3_ROW_PADDING],
            model
                .credentials
                .iter()
                .filter(|credential| {
                    let pattern = model.search_pattern.trim();
                    pattern.is_empty()
                        || credential.site.contains(pattern)
                        || credential.login.contains(pattern)
                })
                .map(|credential| view_credential(credential.id, credential))
                .collect::<Vec<_>>()
        ]
    ]
}

fn view_credential(id: Ulid, credential: &Credential) -> Node<Msg> {
    div![
        C![W3_COL, "l3", "m4", "s6", W3_SECTION],
        div![
            C!["credential", W3_CARD_4, W3_HOVER_OPACITY, POINTER],
            attrs! {At::TabIndex => 0},
            header![
                C![W3_DISPLAY_CONTAINER, W3_THEME, W3_CENTER],
                match credential.otp {
                    OtpType::None => empty!(),
                    _ => span![fa("clock-o"), C![W3_DISPLAY_TOPRIGHT, W3_XLARGE]],
                },
                if credential.logo_url.trim().is_empty() {
                    span![fa("user"), C![W3_XLARGE, W3_DISPLAY_MIDDLE]]
                } else {
                    img![
                        C![W3_IMAGE, W3_DISPLAY_MIDDLE],
                        attrs! {At::Alt => "logo", At::Src => &credential.logo_url}
                    ]
                }
            ],
            div![C![W3_CONTAINER], p![C![CROP], &credential.site]],
            footer![
                C![W3_CONTAINER, W3_THEME_L4],
                h6![C![CROP], em![&credential.login]]
            ],
            mouse_ev(Ev::Click, move |_| Msg::ShowCredential(id)),
            keyboard_event(move || Some(Msg::ShowCredential(id)))
        ]
    ]
}

fn view_add_credential(refs: &Refs, credential: &Credential) -> Node<Msg> {
    const COUNTER: &str = "counter";
    const DIGITS: &str = "digits";
    const LENGTH: &str = "length";
    const LOGIN: &str = "login";
    const SECRET: &str = "secret";
    const SITE: &str = "site";

    let refs = refs.clone();

    div![
        C!["now-credential", W3_MODAL, W3_RESPONSIVE],
        div![
            C![W3_MODAL_CONTENT],
            header![
                header(),
                btn_close(|| Some(Msg::ShowCredentialList)),
                h2![{
                    if credential.id.is_nil() {
                        "Add new credential"
                    } else {
                        "Modification"
                    }
                }]
            ],
            div![
                C![W3_ROW_PADDING, W3_CARD_4, W3_THEME_L4],
                // Website details
                label![
                    C![W3_COL, "m4", "l3"],
                    attrs! {At::For => SITE},
                    "Site name"
                ],
                input![
                    C![
                        W3_COL,
                        "m8",
                        "l9",
                        W3_ROUND_LARGE,
                        W3_BORDER_0,
                        W3_SHOW_INLINE_BLOCK
                    ],
                    attrs! {
                        At::Id => SITE,
                        At::Value => credential.site,
                    },
                    input_ev(
                        Ev::Input,
                        enc!((mut credential) move |site| {
                            credential.site = site;
                            Some(Msg::UpdateModifCredential(Box::new(credential)))
                        }),
                    )
                ],
                label![C![W3_COL, "m4", "l3"], attrs! {At::For => LOGIN}, "Login",],
                input![
                    C![
                        W3_COL,
                        "m8",
                        "l9",
                        W3_ROUND_LARGE,
                        W3_BORDER_0,
                        W3_SHOW_INLINE_BLOCK
                    ],
                    attrs! {
                        At::Id => LOGIN,
                        At::Value => credential.login,
                    },
                    input_ev(
                        Ev::Input,
                        enc!((mut credential) move |login| {
                            credential.login = login;
                            Some(Msg::UpdateModifCredential(Box::new(credential)))
                        })
                    )
                ],
                div![C![W3_COL, "m4", "l3"], "Options"],
                div![
                    C![
                        "credential-options",
                        W3_COL,
                        "m8",
                        "l9",
                        W3_SHOW_INLINE_BLOCK,
                        W3_CENTER
                    ],
                    div![
                        // Lower, Upper, Nums, Symb
                        {
                            [
                                ("a-z", Set::Lowercase),
                                ("A-Z", Set::Uppercase),
                                ("0-9", Set::Numbers),
                                ("%!@", Set::Symbols),
                            ]
                            .iter()
                            .map(|(text, set)| {
                                let mut serials =
                                    credential.settings.get_characterset().get_serials().clone();
                                let password_len = credential.settings.get_password_len();
                                let enabled = serials.contains(&set);
                                let mut credential = credential.clone();

                                toggle_btn(enabled, text, move || {
                                    if !enabled {
                                        serials.push(*set);
                                    } else {
                                        serials.retain(|&x| x != *set);
                                    }

                                    let lower = if serials.contains(&Set::Lowercase) {
                                        LowerCase::Using
                                    } else {
                                        LowerCase::NotUsing
                                    };

                                    let upper = if serials.contains(&Set::Uppercase) {
                                        UpperCase::Using
                                    } else {
                                        UpperCase::NotUsing
                                    };

                                    let number = if serials.contains(&Set::Numbers) {
                                        Numbers::Using
                                    } else {
                                        Numbers::NotUsing
                                    };

                                    let symbol = if serials.contains(&Set::Symbols) {
                                        Symbols::Using
                                    } else {
                                        Symbols::NotUsing
                                    };

                                    let settings =
                                        Settings::new(password_len, lower, upper, number, symbol);
                                    credential.settings = settings;

                                    Msg::UpdateModifCredential(Box::new(credential))
                                })
                            })
                            .collect::<Vec<_>>()
                        }
                    ],
                    div![
                        // Length
                        label![
                            attrs! {At::For => LENGTH},
                            "Length ",
                            input![
                                attrs! {
                                    At::Id => LENGTH,
                                    At::Type => "number",
                                    At::Min => 1,
                                    At::Max => 70,
                                    At::Value => credential.settings.get_password_len(),
                                },
                                input_ev(
                                    Ev::Input,
                                    enc!((mut credential) move |length| {
                                        if let Ok(length) = u8::from_str_radix(&length, 10) {
                                            credential.settings.set_password_len(length);
                                            Some(Msg::UpdateModifCredential(Box::new(credential)))
                                        } else {
                                            None
                                        }
                                    })
                                )
                            ]
                        ]
                    ],
                    div![
                        // Counter
                        label![
                            attrs! {At::For => COUNTER},
                            "Counter ",
                            input![
                                attrs! {
                                    At::Id => COUNTER,
                                    At::Type => "number",
                                    At::Min => 0,
                                    At::Max => u32::MAX,
                                    At::Value => credential.counter,
                                },
                                input_ev(
                                    Ev::Input,
                                    enc!((mut credential) move |counter| {
                                        if let Ok(counter) = u32::from_str_radix(&counter, 10) {
                                            credential.counter = counter;
                                            Some(Msg::UpdateModifCredential(Box::new(credential)))
                                        } else {
                                            None
                                        }
                                    })
                                )
                            ]
                        ]
                    ]
                ],
                // OTP part
                // TODO
                div![C![W3_COL, "m4", "l3"], "Otp"],
                div![
                    C![
                        "credential-options",
                        W3_COL,
                        "m8",
                        "l9",
                        W3_SHOW_INLINE_BLOCK,
                        W3_CENTER
                    ],
                    div![
                        label![
                            input![
                                attrs! {At::Type => "checkbox"},
                                match &credential.otp {
                                    OtpType::None => None,
                                    _ => Some(attrs! {At::Checked => true}),
                                },
                                ev(
                                    Ev::Input,
                                    enc!((mut credential) move |value| {
                                        log!("__cheched", value);

                                        match "value.as_str()" {
                                            "on" => {
                                                let totp = OtpSpecialisation {
                                                    secret_clear: String::new(),
                                                    secret_encoded: Vec::new(),
                                                    digits: 6,
                                                    algorithm: ALGORITHM,
                                                    period: 30,
                                                };

                                                credential.otp = OtpType::Totp(totp, 0);
                                            }
                                            _ => {
                                                credential.otp = OtpType::None;
                                            }
                                        }
                                        Msg::UpdateModifCredential(Box::new(credential))
                                    })
                                )
                            ],
                            " ",
                            "Otp"
                        ],
                        match &credential.otp {
                            OtpType::None => nodes![],
                            OtpType::Totp(totp, start) => {
                                let start = *start;
                                log!("params", &totp);

                                nodes![
                                    div![
                                        // Number of digits
                                        label![
                                            attrs! {At::For => DIGITS},
                                            "Digits ",
                                            input![
                                                attrs! {
                                                    At::Id => DIGITS,
                                                    At::Type => "number",
                                                    At::Min => 6,
                                                    At::Max => 9,
                                                    At::Value => totp.digits,
                                                },
                                                input_ev(
                                                    Ev::Input,
                                                    enc!((mut credential, mut totp) move |digits| {
                                                        if let Ok(digits) =
                                                            u8::from_str_radix(&digits, 10)
                                                        {
                                                            totp.digits = digits;
                                                            credential.otp =
                                                                OtpType::Totp(totp, start);
                                                            Some(Msg::UpdateModifCredential(
                                                                Box::new(credential),
                                                            ))
                                                        } else {
                                                            None
                                                        }
                                                    })
                                                )
                                            ]
                                        ]
                                    ],
                                    div![
                                        // Number of digits
                                        label![
                                            attrs! {At::For => SECRET},
                                            "Secret ",
                                            input![
                                                attrs! {
                                                    At::Id => SECRET,
                                                    At::Type => "text",
                                                    At::Min => 6,
                                                    At::Max => 9,
                                                    At::Value => &totp.secret_clear,
                                                },
                                                input_ev(
                                                    Ev::Input,
                                                    enc!((mut credential, mut totp) move |secret| {
                                                        totp.secret_clear =
                                                            secret.to_ascii_uppercase();
                                                        credential.otp = OtpType::Totp(totp, start);
                                                        Some(Msg::UpdateModifCredential(Box::new(
                                                            credential,
                                                        )))
                                                    })
                                                )
                                            ]
                                        ]
                                    ]
                                ]
                            }
                        }
                    ]
                ]
            ],
            footer![
                footer(),
                C![W3_CENTER],
                p![
                    {
                        let id = credential.id;
                        button![
                            C![W3_BUTTON, W3_THEME_L2, W3_HOVER_THEME],
                            "Cancel",
                            mouse_ev(Ev::Click, move |_| {
                                if id.is_nil() {
                                    Msg::ShowCredentialList
                                } else {
                                    Msg::ShowCredential(id)
                                }
                            })
                        ]
                    },
                    " ",
                    button![
                        C![W3_BUTTON, W3_THEME_L2, W3_HOVER_THEME],
                        el_ref(&refs.credential_save),
                        attrs! {At::Disabled => ""},
                        "Save",
                        mouse_ev(Ev::Click, |_| Msg::AddCredential)
                    ]
                ]
            ],
            mouse_ev(Ev::Click, stop_propagation)
        ],
        mouse_ev(Ev::Click, |_| Msg::ShowCredentialList)
    ]
}

fn view_show_credential(
    lesspass: &LessPass,
    credential: &Credential,
    info: Option<&String>,
    otp: Option<&Otp>,
    password: Option<&String>,
) -> Node<Msg> {
    const MODAL_CONFIRM_DELETE: &str = "modal-confirm-delete";

    let items = vec![
        ("Site name", credential.site.clone()),
        ("Login", credential.login.clone()),
        (
            "Password",
            match password {
                Some(password) => password.clone(),
                None => "Generating password, please wait...".to_string(),
            },
        ),
    ];
    let id = credential.id;

    let hide = || {
        get_element_by_id(MODAL_CONFIRM_DELETE)
            .and_then(|div| div.style().remove_property("display").ok());
        None
    };

    div![
        C!["shown-credential", W3_MODAL, W3_RESPONSIVE],
        div![
            C![W3_MODAL_CONTENT],
            header![
                header(),
                btn_close(|| Some(Msg::ShowCredentialList)),
                h2![&credential.site]
            ],
            div![
                C![W3_ROW_PADDING, W3_CARD_4],
                // Website details
                items.iter().map(|(label, content)| {
                    let content = content.clone();
                    vec![
                        div![C![W3_THEME_L4, W3_COL, "m4", "l3"], &label],
                        div![
                            C![
                                W3_CONTAINER,
                                W3_COL,
                                "m8",
                                "l9",
                                W3_HOVER_THEME,
                                W3_DISPLAY_CONTAINER,
                                "wrap"
                            ],
                            &content,
                            " ",
                            span![fa("copy"), C![W3_DISPLAY_HOVER, POINTER]],
                            mouse_ev(Ev::Click, move |event| {
                                stop_propagation(event);
                                let _ = window()
                                    .navigator()
                                    .clipboard()
                                    .write_text(content.as_str());

                                Msg::ShowInformation(Some("Copied".to_string()))
                            })
                        ],
                    ]
                }),
                // OTP part
                match &credential.otp {
                    OtpType::Totp(settings, start) => {
                        let otp = otp.unwrap();
                        vec![
                            div![C![W3_THEME_L4, W3_COL, "m4", "l3"], "Code"],
                            div![
                                C![W3_CONTAINER, W3_COL, "m8", "l9", W3_DISPLAY_CONTAINER],
                                div![
                                    C![W3_ROW_PADDING, W3_LARGE],
                                    // TOTP
                                    div![
                                        C![
                                            W3_COL,
                                            IF!(otp.value.is_none() => vec![POINTER, W3_WIDE])
                                        ],
                                        style! {St::Width => "auto"},
                                        match &otp.value {
                                            Some(value) => value.clone(),
                                            None => "-".repeat(settings.digits as usize),
                                        },
                                        mouse_ev(Ev::Click, move |event| {
                                            stop_propagation(event);
                                            Msg::ShowOtp(id)
                                        })
                                    ],
                                    " ",
                                    // Time left
                                    span![
                                        C![
                                            W3_COL,
                                            W3_CENTER,
                                            match otp.time {
                                                t if t < (settings.period as i64 / 6) + 1 =>
                                                    W3_THEME_D5,
                                                t if t < (settings.period as i64 / 3) + 1 =>
                                                    W3_THEME_D2,
                                                _ => W3_THEME_L3,
                                            }
                                        ],
                                        style! {St::Width => unit!(2, Unit::Em)},
                                        otp.time
                                    ],
                                ]
                            ],
                        ]
                    }
                    OtpType::None => vec![],
                },
                // Information part
                match info {
                    Some(text) => div![C![W3_TAG, W3_THEME_DARK, W3_DISPLAY_RIGHT], text],
                    None => empty!(),
                }
            ],
            footer![
                footer(),
                div![
                    C![W3_DISPLAY_BOTTOMRIGHT, W3_LARGE],
                    span![
                        fa("edit"),
                        C![W3_BTN, W3_HOVER_THEME],
                        mouse_ev(Ev::Click, move |_| Msg::ShowEditCredential(id))
                    ],
                    span![
                        fa("trash"),
                        C![W3_BTN, W3_HOVER_THEME],
                        mouse_ev(Ev::Click, move |event| {
                            get_element_by_id(MODAL_CONFIRM_DELETE)
                                .and_then(|div| div.style().set_property("display", "block").ok());
                        })
                    ],
                ],
                p!["Footer"]
            ],
            mouse_ev(Ev::Click, stop_propagation),
            // Delete modal window
            div![
                C![W3_MODAL],
                id!(MODAL_CONFIRM_DELETE),
                div![
                    C![W3_MODAL_CONTENT],
                    header![header(), btn_close(move || hide()), h2!["Delete?"]],
                    div![C![W3_PANEL], p!["Are-you sure you want to delete it?"]],
                    footer![
                        footer(),
                        C![W3_CENTER],
                        p![
                            button![
                                C![W3_BUTTON, W3_THEME_L2, W3_HOVER_THEME],
                                "YES",
                                mouse_ev(Ev::Click, move |event| {
                                    stop_propagation(event);
                                    Msg::RemoveCredential(id)
                                })
                            ],
                            " ",
                            button![
                                C![W3_BUTTON, W3_THEME_L2, W3_HOVER_THEME],
                                "NO",
                                mouse_ev(Ev::Click, move |_| hide())
                            ]
                        ]
                    ],
                    mouse_ev(Ev::Click, stop_propagation)
                ],
                mouse_ev(Ev::Click, move |_| hide())
            ]
        ],
        mouse_ev(Ev::Click, |_| Msg::ShowCredentialList)
    ]
}

// ------ ------
//     Start
// ------ ------

// (This function is invoked by `init` function in `index.html`.)
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    // Mount the `app` to the element with id="app"
    App::start("app", init, update, view);
}
