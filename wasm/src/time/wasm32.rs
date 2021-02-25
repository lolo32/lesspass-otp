use wasm_bindgen::prelude::*;

pub use core::time::Duration;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = Date, js_name = now)]
    fn date_now() -> f64;
}

pub fn now() -> i64 {
    date_now() as i64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instant(u64);

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
