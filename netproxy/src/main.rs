#![feature(lookup_host)]
#![allow(unused_imports, unreachable_code)]


use std::io::{Write, Read};



#[cfg(target_family = "windows")]
fn main(){
    unimplemented!();
}


#[cfg(any(target_os = "macos", target_os = "ios")) ]
fn main () {
    println!("im ok, im ok, im ok ...");
}


#[cfg(any(target_os = "linux", target_os = "android"))]
fn main (){
    unimplemented!();
}
