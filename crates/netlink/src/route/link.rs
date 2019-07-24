use crate::sys;

use std::io;


pub struct Links<'a, 'b> {
    pub(crate) socket: &'a mut sys::NetlinkSocket,
    pub(crate) buffer: &'b mut [u8],
}

impl<'a, 'b> Links<'a, 'b> {

}

impl<'a, 'b> Iterator for Links<'a, 'b> {
    type Item = Result<(), io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        unimplemented!()
    }
}