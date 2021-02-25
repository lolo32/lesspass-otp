use enclose::enc;
use seed::{prelude::*, *};

use lesspass_otp::{CharUse, CharacterSet, Set, Settings};

use crate::{
    credential::Credential,
    model::Refs,
    msg::Msg,
    otp::{OtpSpecialisation, OtpType},
    ui::*,
    utils::{char_fn, stop_propagation},
    ALGORITHM,
};

const COUNTER: &str = "counter";
const DIGITS: &str = "digits";
const LENGTH: &str = "length";
const LOGIN: &str = "login";
const SECRET: &str = "secret";
const SITE: &str = "site";

pub fn view_add_credential(refs: &Refs, credential: &Credential) -> Node<Msg> {
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
                            .map(|(text, set): &(&str, Set)| {
                                let mut charset: CharacterSet =
                                    *credential.settings.get_characterset();
                                let tuples = char_fn(*set);
                                let password_len: u8 = credential.settings.get_password_len();
                                let enabled: bool = tuples.0(charset);
                                let mut credential = credential.clone();

                                toggle_btn(enabled, text, move || {
                                    if !enabled {
                                        tuples.1(&mut charset, CharUse::Use);
                                    } else {
                                        tuples.1(&mut charset, CharUse::DontUse);
                                    }
                                    credential.settings = Settings::new(password_len, charset);

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
                                        log!("__checked", value);

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
