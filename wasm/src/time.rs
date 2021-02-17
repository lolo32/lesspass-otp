pub use core::time::Duration;

#[cfg(not(target_arch = "wasm32"))]
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[cfg(not(target_arch = "wasm32"))]
pub type Instant = std::time::Instant;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn date_now() -> f64;
}

#[cfg(target_arch = "wasm32")]
pub fn now() -> i64 {
    date_now() as i64
}

#[cfg(target_arch = "wasm32")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

#[cfg(target_arch = "wasm32")]
impl Instant {
    #[inline]
    pub fn now() -> Self {
        Self(now() as u64)
    }
    #[inline]
    pub fn duration_since(&self, earlier: Self) -> Duration {
        Duration::from_millis(self.0 - earlier.0)
    }
    #[inline]
    pub fn elapsed(self) -> Duration {
        Self::now().duration_since(self)
    }
}
