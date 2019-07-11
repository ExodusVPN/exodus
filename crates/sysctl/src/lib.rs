extern crate libc;

mod sys;
pub use self::sys::*;

#[derive(Debug)]
pub enum Value {
    Node(Vec<u8>),
    String(String),
    Struct { buffer: Vec<u8>, indication: String },
    Int(i64),
    Uint(u64),
    // WARN: https://github.com/freebsd/freebsd/blob/master/sys/sys/sysctl.h#L85
    //       Detail ?
    // #[cfg(target_os = "freebsd")]
    // Temperature, // 16
    Raw(Vec<u8>),
}

impl Value {
    pub fn as_ptr(&self) -> *const u8 {
        match self {
            Value::Node(v) => v.as_ptr(),
            Value::String(v) => v.as_ptr(),
            Value::Struct { buffer, .. } => buffer.as_ptr(),
            Value::Int(v) => v as *const i64 as *const u8,
            Value::Uint(v) => v as *const u64 as *const u8,
            Value::Raw(v) => v.as_ptr(),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Value::Node(v) => v.len(),
            Value::String(v) => v.len(),
            Value::Struct { buffer, .. } => buffer.len(),
            Value::Int(_) => 8,
            Value::Uint(_) => 8,
            Value::Raw(v) => v.len(),
        }
    }
}

