use seed::prelude::*;

use lesspass_otp::charset::{CharUse, CharacterSet, Set};

use crate::ui::W3_THEME_LIGHT;

/// Search if the toggle button is disabled
pub(crate) fn is_button_disabled(el: &ElRef<web_sys::HtmlButtonElement>) -> bool {
    el.get().unwrap().class_list().contains(W3_THEME_LIGHT)
}

/// Helper to stop the event propagation
pub(crate) fn stop_propagation(event: web_sys::MouseEvent) {
    event.stop_propagation();
    event.prevent_default();
}

pub(crate) fn get_ref_el_input(el: &ElRef<web_sys::HtmlInputElement>) -> web_sys::HtmlInputElement {
    el.get().expect("getting input element")
}

pub(crate) fn validate_keyboard(
    keyboard_event: web_sys::KeyboardEvent,
    msg: Option<super::Msg>,
) -> Option<super::Msg> {
    match keyboard_event.key().as_str() {
        super::ENTER_KEY => msg,
        _ => None,
    }
}

pub(crate) struct PassChar {
    pub(crate) class: String,
    pub(crate) character: String,
}

pub(crate) fn format_password(password: &str) -> Vec<PassChar> {
    password
        .chars()
        .map(|c| match c {
            c if c.is_numeric() => PassChar {
                class: "number".to_owned(),
                character: c.to_string(),
            },
            c if c.is_lowercase() => PassChar {
                class: "lower".to_owned(),
                character: c.to_string(),
            },
            c if c.is_uppercase() => PassChar {
                class: "upper".to_owned(),
                character: c.to_string(),
            },
            c => PassChar {
                class: "symbol".to_owned(),
                character: c.to_string(),
            },
        })
        .collect()
}

#[allow(clippy::type_complexity)]
pub(crate) fn char_fn(
    set: Set,
) -> (
    fn(CharacterSet) -> bool,
    fn(&mut CharacterSet, CharUse) -> &mut CharacterSet,
) {
    match set {
        Set::Lowercase => (CharacterSet::is_lower, CharacterSet::set_lower),
        Set::Uppercase => (CharacterSet::is_upper, CharacterSet::set_upper),
        Set::Numbers => (CharacterSet::is_number, CharacterSet::set_number),
        Set::Symbols => (CharacterSet::is_symbol, CharacterSet::set_symbol),
    }
}
