use seed::{prelude::*, *};

use crate::{model::Model, msg::Msg, ui::*};

use self::credential::view_credential;

mod credential;

const SEARCH: &str = "search";

///
/// Display website card list
///
pub fn view_credentials(model: &Model) -> Node<Msg> {
    section![C!["credentials"], search_bar(model), website_list(model),]
}

/// Search bar
fn search_bar(model: &Model) -> Node<Msg> {
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
    ]
}

/// Website card list
fn website_list(model: &Model) -> Node<Msg> {
    div![
        C![W3_ROW_PADDING],
        model
            .credentials
            .iter()
            .filter(|credential| {
                // Filter by data in the search list
                let pattern = model.search_pattern.trim();
                pattern.is_empty()
                    || credential.site.contains(pattern)
                    || credential.login.contains(pattern)
            })
            .map(view_credential)
            .collect::<Vec<_>>()
    ]
}
