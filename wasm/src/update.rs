use seed::log;
use seed::prelude::*;
use ulid::Ulid;

use lesspass_otp::{LessPass, Set};

use crate::{
    model::Model,
    msg::Msg,
    otp::{Otp, OtpType},
    time, Page, ALGORITHM,
};

// ------ ------
//    Update
// ------ ------

// `update` describes how to handle each `Msg`.
pub fn update(msg: Msg, model: &mut Model, orders: &mut impl Orders<Msg>) {
    match msg {
        Msg::Noop => {
            log!("Noop");
        }

        Msg::ToggleMasterType => {
            log!("ToggleMasterType");
            let master = model.refs.master_input.get().expect("get master element");
            match master.type_().as_str() {
                "password" => master.set_type("text"),
                _ => master.set_type("password"),
            }
        }

        // ---------- Master password ----------
        Msg::SetMaster => {
            log!("SetMaster");
            let master = model
                .refs
                .master_input
                .get()
                .expect("get master element")
                .value();
            model.lesspass = LessPass::new(master.as_str(), ALGORITHM).ok();
            orders.send_msg(Msg::ShowCredentialList);
        }
        Msg::CheckMasterFingerprint(master_password) => {
            log!("CheckMasterFingerprint", master_password);
            if let Ok(lesspass) = LessPass::new(master_password.as_str(), ALGORITHM) {
                model.master_fingerprint = lesspass.get_fingerprint(b"");
            }
        }

        // ---------- Credentials ----------
        Msg::ShowCredentialList => {
            log!("ShowCredentialList");
            model.page = Page::None;
            model.otp = None;
            model.credential = None;
        }
        Msg::ShowCredential(id) => {
            log!("ShowCredential", id);
            model.page = Page::Credential(id);
            model.password = None;
            model.password_displayed = false;

            if let Some(credential) = model.credentials.get(id) {
                // Display password
                match credential.password.as_ref() {
                    None => {
                        let id = credential.id;
                        let master = model.lesspass.as_ref().unwrap().clone();
                        let credential = credential.clone();

                        orders.perform_cmd(async move {
                            log!("Stream");
                            Msg::CurrentPassord(
                                id,
                                master
                                    .fut_password_with_algorithm_from_length(
                                        credential.site.as_str(),
                                        credential.login.as_str(),
                                        credential.counter,
                                        &credential.settings,
                                    )
                                    .await
                                    .unwrap(),
                            )
                        });
                    }
                    Some(password) => {
                        orders.send_msg(Msg::CurrentPassord(credential.id, password.clone()));
                    }
                }
                // Display TOTP
                match &credential.otp {
                    OtpType::Totp(settings, time_start) => {
                        let id = id;
                        let period = settings.period;
                        let now =
                            move || i64::from(period) - (time::now() / 1000) % i64::from(period);
                        model.otp = Some(Otp {
                            time: now(),
                            value: None,
                            stream: {
                                orders.stream_with_handle(streams::interval(250, move || {
                                    Msg::SetTotpTime(id, now())
                                }))
                            },
                        });
                    }
                    OtpType::None => {}
                }
            }
        }
        Msg::ShowEditCredential(id) => {
            log!("ShowEditCredential", id);
            if let Some(credential) = model.credentials.get(id) {
                let mut credential = credential.clone();
                credential.password = None;
                model.credential = Some(credential);

                model.page = Page::AddCredential;
            }
        }
        Msg::UpdateModifCredential(box_credential) => {
            log!("UpdateModifCredential", box_credential);
            model.credential = Some(*box_credential);
            orders.send_msg(Msg::ValidateNewCredentialData);
        }
        Msg::ShowAddCredential => {
            log!("ShowAddCredential");
            model.credential = Some(Default::default());
            model.page = Page::AddCredential;
        }
        Msg::CurrentPassord(id, password) => {
            log!(password);
            model.password = Some(password.clone());
            if let Some(credential) = model.credentials.get_mut(id) {
                credential.password = Some(password);
            }
        }
        Msg::ShowPassword(display) => model.password_displayed = display,

        Msg::AddCredential => {
            log!("AddCredential");
            let credential_ref = model.credential.as_ref().expect("getting credential");
            let mut credential = credential_ref.clone();

            let id = if credential.id.is_nil() {
                // If it's a new, generate a new id
                Ulid::new()
            } else {
                credential.id
            };

            // OTP Part
            match &credential_ref.otp {
                OtpType::None => {}
                OtpType::Totp(params, ts) => {}
            }

            if let Some(c) = model.credentials.get_mut(credential.id) {
                // Modification
                *c = credential;
            } else {
                credential.id = id;
                model.credentials.insert(credential);
            }

            model.save();

            // Show the saved credential
            orders.send_msg(Msg::ShowCredential(id));
        }
        Msg::RemoveCredential(id) => {
            log!("RemoveCredential", id);
            if let Some(_credential) = model.credentials.remove(id) {
                model.save();
            }
            orders.send_msg(Msg::ShowCredentialList);
        }
        Msg::SetLogo => {
            log!("SetLogo");
            model.save();
        }

        // ---------- Otp ----------
        Msg::AddOtp(id, otp) => {
            log!("AddOtp", id, otp);
            model.save();
        }
        Msg::RemoveOtp(id) => {
            log!("RemoveOtp", id);
            model.save();
        }
        Msg::SetTotpTime(id, t) => {
            // log!("SetTotpTime", t);
            if model.otp.is_some() {
                let otp = model.otp.as_mut().unwrap();
                if t == otp.time {
                    // Same time, so no new rendering
                    orders.skip();
                    return;
                }
                if otp.value.is_some() && t > otp.time {
                    // Hide the code after it's expiration
                    otp.value = None;
                    // Show new valid code after it's expiration
                    //orders.send_msg(Msg::ShowOtp(id));
                }

                otp.time = t;
            } else {
                orders.skip();
            }
        }
        Msg::ShowOtp(id) => {
            log!("ShowOtp", id);
            if let Some(credential) = model.credentials.get(id) {
                if let OtpType::Totp(settings, timestamp) = &credential.otp {
                    let otp = lesspass_otp::Otp::new(
                        &lesspass_otp::decode_base32(&settings.secret_clear).unwrap(),
                        settings.digits,
                        Some(settings.algorithm),
                        Some(settings.period),
                        None,
                    )
                    .unwrap();
                    model.otp.as_mut().unwrap().value =
                        Some(otp.totp_from_ts((time::now() / 1000) as u64));
                }
            }
        }

        // ---------- Search ----------
        Msg::SearchCredential(search) => {
            log!("SearchCredential", search);
            model.search_pattern = search;
        }

        // ---------- Information message ----------
        Msg::ShowInformation(message) => {
            log!("ShowInformation", message);

            if message.is_some() {
                orders.perform_cmd(cmds::timeout(900, || Msg::ShowInformation(None)));
            }
            model.info = message;
        }

        Msg::ValidateNewCredentialData => {
            log!("ValidateNewCredentialData");
            orders.skip();

            if let Some(credential) = model.credential.as_ref() {
                let disable = |val: bool| {
                    model
                        .refs
                        .credential_save
                        .get()
                        .expect("getting save element")
                        .set_disabled(val);
                };
                let charsets = credential.settings.get_characterset().get_serials();

                if !charsets.contains(&Set::Lowercase)
                    && !charsets.contains(&Set::Uppercase)
                    && !charsets.contains(&Set::Numbers)
                    && !charsets.contains(&Set::Symbols)
                    || credential.site.trim().is_empty()
                    || credential.login.trim().is_empty()
                {
                    disable(true);
                } else {
                    disable(false);
                }
            }
        }

        Msg::Download => {
            log!("Download");
        }
        Msg::Upload => {
            log!("Upload");
        }
    }
}
