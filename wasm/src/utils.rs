use seed::prelude::*;
use ulid::Ulid;

use crate::{ui::*, Credential, Model, STORAGE_KEY};

/// Search if the toggle button is disabled
pub(crate) fn is_button_disabled(el: &ElRef<web_sys::HtmlButtonElement>) -> bool {
    el.get().unwrap().class_list().contains(W3_THEME_LIGHT)
}

/// Return the index in the credential list from the id
pub(crate) fn search_credential(
    credentials: &[Credential],
    id: Ulid,
) -> Option<(usize, &Credential)> {
    if let Some(index) = credentials.iter().position(|c| c.id == id) {
        Some((index, credentials.get(index).as_ref().unwrap()))
    } else {
        None
    }
    // for (index, credential) in credentials.iter().enumerate() {
    //     if credential.id == id {
    //         return Some((index, credential));
    //     }
    // }
    //
    // None
}

/// Save the credential list in the LocalStorage
pub(crate) fn save_storage(model: &Model) {
    LocalStorage::insert(STORAGE_KEY, &model.credentials)
        .expect("save credentials to LocalStorage");
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
