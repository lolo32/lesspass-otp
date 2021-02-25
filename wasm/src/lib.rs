//#![deny(missing_docs)]
#![deny(missing_copy_implementations)]
#![deny(missing_debug_implementations)]
#![deny(trivial_numeric_casts)]
//#![deny(unreachable_pub)]
//#![deny(unsafe_code)]
#![deny(unused_extern_crates)]
#![deny(unused_qualifications)]
#![allow(clippy::wildcard_imports)]

use seed::{prelude::*, *};
use ulid::Ulid;

use lesspass_otp::{Algorithm, LessPass};

use crate::credential::Credential;
use crate::credentials::Credentials;
use crate::model::Model;
use crate::msg::Msg;
use crate::otp::OtpType;
use crate::utils::*;

mod credential;
mod credentials;
mod model;
mod msg;
mod otp;
mod time;
mod ui;
mod update;
mod utils;
mod view;

const ALGORITHM: Algorithm = Algorithm::SHA256;
const STORAGE_KEY: &str = "lesspass-seed";

const ENTER_KEY: &str = "Enter";

// ------ ------
//     Init
// ------ ------

// `init` describes what should happen when your app started.
fn init(_url: Url, _orders: &mut impl Orders<Msg>) -> Model {
    Model {
        refs: Default::default(),
        lesspass: None,
        master_fingerprint: LessPass::new("", Algorithm::SHA256)
            .unwrap()
            .get_fingerprint(b""),
        credentials: Credentials::new_from_localstorage(),
        search_pattern: "".to_owned(),
        page: Page::None,
        info: Default::default(),
        otp: None,
        password_displayed: false,
        password: None,
        credential: None,
    }
    .add_mock_data()
}

#[derive(Debug)]
enum Page {
    None,
    Credential(Ulid),
    AddCredential,
}

#[derive(Debug, Default)]
struct Info {
    message: Option<String>,
    stream: Option<StreamHandle>,
}

// ------ ------
//     Start
// ------ ------

// (This function is invoked by `init` function in `index.html`.)
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    // Mount the `app` to the element with id="app"
    App::start("app", init, crate::update::update, crate::view::view);
}
