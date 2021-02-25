use seed::{prelude::*, *};

use lesspass_otp::LessPass;

use crate::{
    credential::Credential,
    msg::Msg,
    otp::{Otp, OtpType},
    ui::*,
    utils::{format_password, stop_propagation},
};
use ulid::Ulid;

const MODAL_CONFIRM_DELETE: &str = "modal-confirm-delete";

pub fn view_show_credential(
    lesspass: &LessPass,
    credential: &Credential,
    info: Option<&String>,
    otp: Option<&Otp>,
    password: Option<&String>,
    display_password: bool,
) -> Node<Msg> {
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
                display_field_line("Site name", &credential.site),
                display_field_line("Login", &credential.login),
                display_password_line(
                    "Password",
                    match password {
                        Some(password) => &password,
                        None => "Generating password, please wait...",
                    },
                    display_password
                ),
                display_field_otp(id, otp, &credential.otp),
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

fn display_line(label: &str, content: &str, node: Node<Msg>) -> Vec<Node<Msg>> {
    let content = content.to_owned();

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
            node,
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
}

fn display_field_line(label: &str, content: &str) -> Vec<Node<Msg>> {
    display_line(label, content, span![content])
}

fn display_password_line(label: &str, content: &str, display_password: bool) -> Vec<Node<Msg>> {
    let node = {
        let mut pass_vec = Vec::new();
        if display_password {
            let _ = format_password(content)
                .iter()
                .map(|c| pass_vec.push(span![C![&c.class], &c.character]))
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
    };

    display_line(label, content, node)
}

fn display_field_otp(id: Ulid, otp: Option<&Otp>, otp_type: &OtpType) -> Vec<Node<Msg>> {
    // OTP part
    match otp_type {
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
                            C![W3_COL, IF!(otp.value.is_none() => vec![POINTER, W3_WIDE])],
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
                                    // 1/6 time left
                                    t if t < (settings.period as i64 / 6) + 1 => W3_THEME_D5,
                                    // 1/3 time left
                                    t if t < (settings.period as i64 / 3) + 1 => W3_THEME_D2,
                                    // 2/3 time left
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
    }
}
