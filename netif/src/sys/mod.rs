#![cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]
#![allow(non_camel_case_types, non_snake_case, dead_code)]

#![cfg(not(windows))]
pub use libc::*;

cfg_if! {
    if #[cfg(any(target_os = "macos", target_os = "freebsd"))] {
        mod bsd;
        pub use self::bsd::*;
    }
}

cfg_if! {
    if #[cfg(target_os = "macos")] {
        mod macos;
        pub use self::macos::*;
    } else if #[cfg(target_os = "linux")] {
        mod linux;
        pub use self::linux::*;
    } else if #[cfg(windows)] {
        mod windows;
        pub use self::windows::*;
    }
}

