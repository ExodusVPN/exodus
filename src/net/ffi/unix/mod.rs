


#[cfg(any(target_os = "macos", target_os = "ios"))]
mod xnu;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use xnu::*;


#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use linux::*;
