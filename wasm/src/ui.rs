use seed::{prelude::*, *};

use super::Msg;

pub(crate) const CROP: &str = "crop";
pub(crate) const POINTER: &str = "pointer";

pub(crate) const W3_BTN: &str = "w3-btn";
pub(crate) const W3_BUTTON: &str = "w3-button";
pub(crate) const W3_IMAGE: &str = "w3-image";

pub(crate) const W3_THEME_LIGHT: &str = "w3-theme-light";
pub(crate) const W3_THEME_L4: &str = "w3-theme-l4";
pub(crate) const W3_THEME_L3: &str = "w3-theme-l3";
pub(crate) const W3_THEME_L2: &str = "w3-theme-l2";
pub(crate) const W3_THEME: &str = "w3-theme";
pub(crate) const W3_THEME_D1: &str = "w3-theme-d1";
pub(crate) const W3_THEME_D2: &str = "w3-theme-d2";
pub(crate) const W3_THEME_D3: &str = "w3-theme-d3";
pub(crate) const W3_THEME_D5: &str = "w3-theme-d5";
pub(crate) const W3_THEME_ACTION: &str = "w3-theme-action";
pub(crate) const W3_THEME_DARK: &str = "w3-theme-dark";
pub(crate) const W3_HOVER_THEME: &str = "w3-hover-theme";
pub(crate) const W3_BORDER_THEME: &str = "w3-border-theme";

pub(crate) const W3_WIDE: &str = "w3-wide";
pub(crate) const W3_CENTER: &str = "w3-center";
pub(crate) const W3_RIGHT: &str = "w3-right";
pub(crate) const W3_RIGHT_ALIGN: &str = "w3-right-align";
pub(crate) const W3_DISPLAY_TOPRIGHT: &str = "w3-display-topright";
pub(crate) const W3_DISPLAY_RIGHT: &str = "w3-display-right";
pub(crate) const W3_DISPLAY_MIDDLE: &str = "w3-display-middle";
pub(crate) const W3_DISPLAY_BOTTOMRIGHT: &str = "w3-display-bottomright";
pub(crate) const W3_DISPLAY_BOTTOM: &str = "w3-display-bottom";
pub(crate) const W3_DISPLAY_CONTAINER: &str = "w3-display-container";
pub(crate) const W3_DISPLAY_HOVER: &str = "w3-display-hover";

pub(crate) const W3_CARD_4: &str = "w3-card-4";
pub(crate) const W3_COL: &str = "w3-col";
pub(crate) const W3_ROW_PADDING: &str = "w3-row-padding";
pub(crate) const W3_CONTAINER: &str = "w3-container";
pub(crate) const W3_PANEL: &str = "w3-panel";
pub(crate) const W3_TAG: &str = "w3-tag";
pub(crate) const W3_SECTION: &str = "w3-section";
pub(crate) const W3_RESPONSIVE: &str = "w3-responsive";
pub(crate) const W3_MODAL: &str = "w3-modal";
pub(crate) const W3_MODAL_CONTENT: &str = "w3-modal-content";
pub(crate) const W3_SHOW_INLINE_BLOCK: &str = "w3-show-inline-block";

pub(crate) const W3_MEDIUM: &str = "w3-medium";
pub(crate) const W3_LARGE: &str = "w3-large";
pub(crate) const W3_XLARGE: &str = "w3-xlarge";
pub(crate) const W3_PADDING_SMALL: &str = "w3-padding-small";
pub(crate) const W3_PADDING_16: &str = "w3-padding-16";

pub(crate) const W3_BORDER_0: &str = "w3-border-0";
pub(crate) const W3_ROUND_LARGE: &str = "w3-round-large";

pub(crate) const W3_HOVER_OPACITY: &str = "w3-hover-opacity";

pub(crate) fn btn_close<F>(cb: F) -> Node<Msg>
where
    F: FnOnce() -> Option<Msg> + Clone + 'static,
{
    let cb2 = cb.clone();

    span![
        C![
            W3_DISPLAY_TOPRIGHT,
            W3_BTN,
            W3_LARGE,
            W3_HOVER_THEME,
            "fa",
            "fa-times"
        ],
        mouse_ev(Ev::Click, move |_| cb()),
        keyboard_event(cb2)
    ]
}

pub(crate) fn header() -> Attrs {
    C![W3_CONTAINER, W3_THEME_D1]
}

pub(crate) fn footer() -> Attrs {
    C![W3_CONTAINER, W3_THEME_D3]
}

pub(crate) fn toggle_btn<F>(btn_enabled: bool, text: &str, cb: F) -> Node<Msg>
where
    F: FnOnce() -> Msg + Clone + 'static,
{
    let cb2 = cb.clone();

    button![
        C![
            W3_BUTTON,
            {
                if btn_enabled {
                    W3_THEME_DARK
                } else {
                    W3_THEME_LIGHT
                }
            },
            W3_HOVER_THEME,
            W3_PADDING_SMALL
        ],
        attrs! {At::TabIndex => 0},
        text,
        mouse_ev(Ev::Click, move |event| {
            super::stop_propagation(event);
            cb()
        }),
        keyboard_event(|| Some(cb2()))
    ]
}

pub(crate) fn keyboard_event<F>(cb: F) -> EventHandler<Msg>
where
    F: FnOnce() -> Option<Msg> + Clone + 'static,
{
    keyboard_ev(Ev::KeyDown, move |key_event| {
        super::utils::validate_keyboard(key_event, cb())
    })
}

pub(crate) fn get_element_by_id(id: &str) -> Option<web_sys::HtmlDivElement> {
    document()
        .get_element_by_id(id)
        .and_then(|element| element.dyn_into::<web_sys::HtmlDivElement>().ok())
}

pub(crate) fn fa(name: &'static str) -> Attrs {
    C!["fa", "fa-".to_owned() + name]
}
