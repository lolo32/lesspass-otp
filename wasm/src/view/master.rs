use seed::{prelude::*, *};

use lesspass_otp::Fingerprint;

use crate::{msg::Msg, ui::*};

const MASTER_PASSWORD: &str = "master-password";

pub fn view_master(
    master_fingerprint: Fingerprint,
    master_input_ref: &ElRef<web_sys::HtmlInputElement>,
) -> Node<Msg> {
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
