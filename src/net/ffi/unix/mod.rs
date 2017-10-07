


if #[cfg(any(target_os = "macos", target_os = "ios"))] {
    mod xnu;
    pub use xnu::*;
} else if #[cfg(any(target_os = "linux", target_os = "android"))] {
    mod linux;
    pub use linux::*;
}