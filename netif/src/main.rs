#![allow(unused_imports, unused_assignments, unused_variables)]
// #![cfg(all(unix, windows))]

extern crate libc;
extern crate ipnetwork;

#[cfg(windows)]
extern crate winapi;
// #[cfg(unix)]
extern crate nix;


pub mod sys;
pub mod interface;


fn main() {
    let ifaces = interface::interfaces();
    for x in ifaces{
        println!("{}", x);
    }
    
}
