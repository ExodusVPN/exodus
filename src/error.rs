
use std::io;


#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    
}
