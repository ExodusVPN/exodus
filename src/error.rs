
use std::io;


#[derive(Debug)]
pub enum Error {
    Io(io::Error),
}
