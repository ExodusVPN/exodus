extern crate libc;

mod sys;
pub use self::sys::*;

#[derive(Debug, PartialEq, Clone)]
pub enum Value {
    String(String),
    Struct { buffer: Vec<u8>, indication: String },
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    // WARN: https://github.com/freebsd/freebsd/blob/master/sys/sys/sysctl.h#L85
    //       Detail ?
    // #[cfg(target_os = "freebsd")]
    // Temperature, // 16
    Raw(Vec<u8>),
}

impl Value {
    pub fn as_ptr(&self) -> *const u8 {
        match self {
            Value::String(v) => v.as_ptr(),
            Value::Struct { buffer, .. } => buffer.as_ptr(),
            Value::I8(v) => v as *const i8 as *const u8,
            Value::I16(v) => v as *const i16 as *const u8,
            Value::I32(v) => v as *const i32 as *const u8,
            Value::I64(v) => v as *const i64 as *const u8,

            Value::U8(v) => v as *const u8 as *const u8,
            Value::U16(v) => v as *const u16 as *const u8,
            Value::U32(v) => v as *const u32 as *const u8,
            Value::U64(v) => v as *const u64 as *const u8,

            Value::Raw(v) => v.as_ptr(),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Value::String(v) => v.len(),
            Value::Struct { buffer, .. } => buffer.len(),
            Value::I8(_) | Value::U8(_) => 1,
            Value::I16(_) | Value::U16(_) => 2,
            Value::I32(_) | Value::U32(_) => 4,
            Value::I64(_) | Value::U64(_) => 8,
            Value::Raw(v) => v.len(),
        }
    }
}

