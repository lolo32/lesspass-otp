use std::{cmp::Ordering, slice::Iter};

use seed::prelude::{LocalStorage, WebStorage};
use ulid::Ulid;

use crate::{Credential, STORAGE_KEY};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Credentials(Vec<Credential>);

impl Credentials {
    pub fn new_from_localstorage() -> Self {
        Self(LocalStorage::get(STORAGE_KEY).unwrap_or_default())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn push(&mut self, credential: Credential) {
        self.0.push(credential)
    }

    pub fn get(&self, id: Ulid) -> Option<&Credential> {
        if let Some(index) = self.0.iter().position(|c| c.id == id) {
            self.0.get(index)
        } else {
            None
        }
    }

    pub fn get_mut(&mut self, id: Ulid) -> Option<&mut Credential> {
        if let Some(index) = self.index(id) {
            self.0.get_mut(index)
        } else {
            None
        }
    }

    pub fn insert(&mut self, credential: Credential) {
        // New credential
        let mut index = self.0.len();
        // Insert in ordering, based on site name and login information
        for (i, cred) in self.0.iter().enumerate() {
            match cred.site.cmp(&credential.site) {
                // Lower website name, so adding maybe to the next iteration
                Ordering::Less => {}
                // Same website name, try to compare the login name
                Ordering::Equal if cred.login.cmp(&credential.login) == Ordering::Less => {}
                _ => {
                    index = i;
                    break;
                }
            }
        }

        if index == self.0.len() {
            // If index is at the last position, push the element
            self.0.push(credential);
        } else {
            // or insert it at the `index` position
            self.0.insert(index, credential);
        }
    }

    pub fn iter(&self) -> Iter<'_, Credential> {
        self.0.iter()
    }

    pub fn index(&self, id: Ulid) -> Option<usize> {
        self.0.iter().position(|c| c.id == id)
    }

    pub fn remove(&mut self, id: Ulid) -> Option<Credential> {
        if let Some(index) = self.index(id) {
            Some(self.0.remove(index))
        } else {
            None
        }
    }
}
