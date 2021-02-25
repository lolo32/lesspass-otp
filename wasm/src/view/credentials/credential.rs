use seed::{prelude::*, *};
use ulid::Ulid;

use crate::{credential::Credential, msg::Msg, otp::OtpType, ui::*};

pub fn view_credential(id: Ulid, credential: &Credential) -> Node<Msg> {
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
