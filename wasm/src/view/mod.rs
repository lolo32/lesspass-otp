use seed::{prelude::*, *};

use crate::{model::Model, msg::Msg, Page};

use self::{
    add_credential::view_add_credential, credentials::view_credentials, master::view_master,
    show_credential::view_show_credential,
};

mod add_credential;
mod credentials;
mod master;
mod show_credential;

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
