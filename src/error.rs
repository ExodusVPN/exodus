
use std::io;
use openssl::error::ErrorStack;


#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    OpenSsl(ErrorStack)
}