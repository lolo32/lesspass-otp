#[allow(unused)]
mod other;
mod wasm32;

#[cfg(not(target_arch = "wasm32"))]
pub use other::{now, Instant};

#[cfg(target_arch = "wasm32")]
pub use wasm32::{now, Instant};
