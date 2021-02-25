use enclose::enc;
use seed::{prelude::*, *};
use ulid::Ulid;

use lesspass_otp::{CharUse, CharacterSet, Fingerprint, LessPass, Set, Settings};

use crate::{
    credential::Credential,
    model::{Model, Refs},
    msg::Msg,
    otp::{Otp, OtpSpecialisation, OtpType},
    ui::*,
    utils::{char_fn, format_password, stop_propagation},
    Page, ALGORITHM,
};

// ------ ------
//     View
// ------ ------

// `view` describes what to display.
pub fn view(model: &Model) -> Vec<Node<Msg>> {
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
                if let Some(credential) = model.credentials.get(*id) {
                    log!("Page::Credential", id, "credential");
                    view_show_credential(
                        model.lesspass.as_ref().unwrap(),
                        credential,
                        model.info.as_ref(),
                        model.otp.as_ref(),
                        model.password.as_ref(),
                        model.password_displayed,
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

fn view_show_credential(
    lesspass: &LessPass,
    credential: &Credential,
    info: Option<&String>,
    otp: Option<&Otp>,
    password: Option<&String>,
    display_password: bool,
) -> Node<Msg> {
    const MODAL_CONFIRM_DELETE: &str = "modal-confirm-delete";

    let items = vec![
        ("Site name", credential.site.clone()),
        ("Login", credential.login.clone()),
        (
            "Password",
            match password {
                Some(password) => password.clone(),
                None => "Generating password, please wait...".to_owned(),
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
                            match password {
                                Some(_) =>
                                    if label == &"Password" {
                                        // Password field
                                        let mut pass_vec = Vec::new();
                                        if display_password {
                                            let _ = format_password(&content)
                                                .iter()
                                                .map(|c| {
                                                    pass_vec.push(span![C![&c.class], &c.character])
                                                })
                                                .collect::<Vec<_>>();
                                        } else {
                                            pass_vec.push(span!["············"]);
                                        }
                                        span![
                                            span![
                                                if display_password {
                                                    fa("eye-slash")
                                                } else {
                                                    fa("eye")
                                                },
                                                C![POINTER],
                                                mouse_ev(Ev::Click, move |event| {
                                                    stop_propagation(event);
                                                    Msg::ShowPassword(!display_password)
                                                })
                                            ],
                                            " ",
                                            span![pass_vec, C!["w3-monospace"]]
                                        ]
                                    } else {
                                        // Other field
                                        span![&content]
                                    },
                                None => span![&content],
                            },
                            " ",
                            span![fa("copy"), C![W3_DISPLAY_HOVER, POINTER]],
                            mouse_ev(Ev::Click, move |event| {
                                stop_propagation(event);
                                let _ = window()
                                    .navigator()
                                    .clipboard()
                                    .write_text(content.as_str());

                                Msg::ShowInformation(Some("Copied".to_owned()))
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
                        mouse_ev(Ev::Click, move |_| {
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
                    header![header(), btn_close(hide), h2!["Delete?"]],
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
