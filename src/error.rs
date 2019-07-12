
use std::io;
use std::fmt;


#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
}

