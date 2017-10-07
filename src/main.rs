#![feature(lookup_host)]
#![allow(unused_imports, unreachable_code)]

extern crate ssh2;
extern crate trust_dns_resolver;

use std::io::{Write, Read};



#[cfg(any(target_os = "linux", target_os = "android"))]
fn linux_main {

}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn xnu_main {
    
}

fn bsd_main() {

}

fn main() {
    if #[cfg(target_family = "unix")] {
        if #[cfg(any(target_os = "linux", target_os = "android"))] {
            linux_main()
        } else if #[cfg(any(target_os = "macos", target_os = "ios"))] {
            xnu_main()
        } else if #[cfg(any(target_os = "freebsd", target_os = "dragonfly", 
                            target_os = "openbsd", target_os = "netbsd", 
                            target_os = "bitrig"))] {
            panic!("BSD 系统暂不支持！");
        } else {
            panic!("Ooops ...");
        }
    } else if #[cfg(target_family = "windows")] {
        panic!("windows 系统暂不支持！");
    } else {
        panic!("只支持 windows/unix 系统。");
    }
}

