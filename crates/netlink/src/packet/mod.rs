use crate::sys;

pub mod netlink;
pub mod rt_route;

#[derive(Debug, Clone)]
pub struct Packet {
    inner: Vec<u8>,
}

impl Packet {
    pub fn new() -> Self {
        let mut inner = Vec::with_capacity(sys::MAX_NL_LENGTH);
        inner.resize(sys::MAX_NL_LENGTH, 0u8);

        Self { inner }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.inner.as_ptr()
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }
}