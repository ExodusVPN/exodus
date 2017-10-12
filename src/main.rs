#![feature(lookup_host)]
#![allow(unused_imports, unreachable_code)]


use std::io::{Write, Read};



#[cfg(target_family = "windows")]
fn main(){
    unimplemented!();
}


#[cfg(all(target_family = "unix", any(target_os = "macos", target_os = "ios"
                                      target_os = "freebsd", target_os = "bitrig", 
                                      target_os = "dragonfly", 
                                      target_os = "netbsd", target_os = "openbsd")
))]
fn main {
    println!("im ok, im ok, im ok ...");
}


#[cfg(all(target_family = "unix", any(target_os = "linux", target_os = "android")))]
fn main {
    unimplemented!();
}

#[cfg(any(not(target_family = "windows", target_family = "unix")
          not(target_os = "macos", target_os = "ios", target_os = "linux", target_os = "android")
))]
fn main (){
    unimplemented!();
}


