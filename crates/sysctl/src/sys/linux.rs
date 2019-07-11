use crate::Value;

use libc;

use std::str::FromStr;
use std::io::{self, Read, Write};
use std::fs::{OpenOptions, ReadDir,};
use std::path::{Path, PathBuf,};


// largest number of components supported
pub const CTL_MAXNAME: usize = 10;

#[cfg(target_os = "linux")]
const PATH_PREFIX: &'static str = "/proc/sys";


#[cfg(target_os = "linux")]
const ROOT_PATH: &'static str = "/proc/sys/kernel";

// NOTE: for develop
#[cfg(not(target_os = "linux"))]
const PATH_PREFIX: &'static str = concat!(env!("PWD"), "/proc/sys");
#[cfg(not(target_os = "linux"))]
const ROOT_PATH: &'static str = concat!(env!("PWD"), "/proc/sys/kernel");

// Top-level names
pub const CTL_KERN: libc::c_int = 1; // General kernel info and control
pub const CTL_VM: libc::c_int = 2; // VM management
pub const CTL_NET: libc::c_int = 3; // Networking
pub const CTL_PROC: libc::c_int = 4; // removal breaks strace(1) compilation
pub const CTL_FS: libc::c_int = 5; // Filesystems
pub const CTL_DEBUG: libc::c_int = 6; // Debugging
pub const CTL_DEV: libc::c_int = 7; // Devices
pub const CTL_BUS: libc::c_int = 8; // Busses
pub const CTL_ABI: libc::c_int = 9; // Binary emulation
pub const CTL_CPU: libc::c_int = 10; // CPU stuff (speed scaling, etc)
pub const CTL_ARLAN: libc::c_int = 254; // arlan wireless driver
pub const CTL_S390DBF: libc::c_int = 5677; // s390 debug
pub const CTL_SUNRPC: libc::c_int = 7249; // sunrpc debug
pub const CTL_PM: libc::c_int = 9899; // frv power management
pub const CTL_FRV: libc::c_int = 9898; // frv specific sysctls


// TODO:
// Metadata Table
pub const TABLE: &[(&'static str, Kind)] = &[
    ("abi", Kind::Node),
    ("abi.vsyscall32", Kind::I32),
    
    ("debug", Kind::Node),
    ("dev", Kind::Node),
    ("fs", Kind::Node),

    ("kernel", Kind::Node,),
    ("kernel.ostype", Kind::String),
    ("kernel.osrelease", Kind::String),
    ("kernel.version", Kind::String),
    ("kernel.panic", Kind::I32),

    ("net", Kind::Node),
    ("net.ipv4", Kind::Node),
    ("net.ipv4.ip_forward", Kind::I32),
    ("net.ipv4.conf", Kind::Node),
    ("net.ipv4.conf.all", Kind::Node),
    ("net.ipv4.conf.all.forwarding", Kind::I32),
    ("net.ipv4.conf.default", Kind::Node),
    ("net.ipv4.conf.default.forwarding", Kind::I32),
    ("net.ipv6", Kind::Node),
    ("net.ipv6.conf", Kind::Node),
    ("net.ipv6.conf.all", Kind::Node),
    ("net.ipv6.conf.all.forwarding", Kind::I32),
    ("net.ipv6.conf.default", Kind::Node),
    ("net.ipv6.conf.default.forwarding", Kind::I32),

    ("user", Kind::Node),
    ("vm", Kind::Node),
    ("vm.page-cluster", Kind::I32),
];


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Kind {
    Node,
    String,
    Struct,
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    Unknow,
}

#[derive(Debug)]
pub struct Metadata {
    kind: Kind,
    // format
    indication: &'static str,
}


#[derive(Debug, Clone)]
pub struct Mib {
    path: PathBuf,
}

impl Mib {
    #[inline]
    pub fn name(&self) -> Result<String, io::Error> {
        let name = self.path
                        .strip_prefix(PATH_PREFIX)
                        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("{}", e)))?
                        .to_str()
                        .ok_or(io::Error::new(io::ErrorKind::Other, "Not a valid UTF-8 sequence"))?;
        Ok(name.replace("/", "."))
    }
    
    // Get Value by Mib
    #[inline]
    pub fn value(&self) -> Result<Value, io::Error> {
        let name = self.name()?;
        let mut kind = Kind::Unknow;
        for item in TABLE {
            if name == item.0 {
                kind = item.1;
                break;
            }
        }

        if !self.path.is_file() || kind == Kind::Node {
            return Err(io::Error::new(io::ErrorKind::Other, "Can not get value from a Node."));
        }

        let mut file = OpenOptions::new().read(true).write(false).open(&self.path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;

        if buf.ends_with(&[b'\n']) {
            buf.truncate(buf.len() - 1);
        }

        let val_s = unsafe { std::str::from_utf8_unchecked(&buf) };

        let val = match kind {
            Kind::Node => unreachable!(),
            Kind::String => unsafe { Value::String(String::from_utf8_unchecked(buf)) },
            Kind::Struct => Value::Struct { buffer: buf, indication: "".to_string() },
            Kind::I8 => {
                let n = val_s.parse::<i8>()
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
                Value::I8(n)
            },
            Kind::I16 => {
                let n = val_s.parse::<i16>()
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
                Value::I16(n)
            }
            Kind::I32 => {
                let n = val_s.parse::<i32>()
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
                Value::I32(n)
            }
            Kind::I64 => {
                let n = val_s.parse::<i64>()
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
                Value::I64(n)
            }
            Kind::U8 => {
                let n = val_s.parse::<u8>()
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
                Value::U8(n)
            },
            Kind::U16 => {
                let n = val_s.parse::<u16>()
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
                Value::U16(n)
            }
            Kind::U32 => {
                let n = val_s.parse::<u32>()
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
                Value::U32(n)
            }
            Kind::U64 => {
                let n = val_s.parse::<u64>()
                            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{}", e)))?;
                Value::U64(n)
            }
            Kind::Unknow => Value::Raw(buf),
        };

        Ok(val)
    }

    // Set Value By Mib
    #[inline]
    pub fn set_value(&self, val: Value) -> Result<Value, io::Error> {
        let mut file = OpenOptions::new().read(false).write(true).open(&self.path)?;

        match val {
            Value::String(s) => {
                file.write_all(s.as_bytes())?;
            },
            Value::Struct { buffer, .. } => {
                file.write_all(&buffer)?;
            },
            Value::I8(v) => {
                let s = v.to_string();
                file.write_all(&s.as_bytes())?;
            },
            Value::I16(v) => {
                let s = v.to_string();
                file.write_all(&s.as_bytes())?;
            },
            Value::I32(v) => {
                let s = v.to_string();
                file.write_all(&s.as_bytes())?;
            },
            Value::I64(v) => {
                let s = v.to_string();
                file.write_all(&s.as_bytes())?;
            },
            Value::U8(v) => {
                let s = v.to_string();
                file.write_all(&s.as_bytes())?;
            },
            Value::U16(v) => {
                let s = v.to_string();
                file.write_all(&s.as_bytes())?;
            },
            Value::U32(v) => {
                let s = v.to_string();
                file.write_all(&s.as_bytes())?;
            },
            Value::U64(v) => {
                let s = v.to_string();
                file.write_all(&s.as_bytes())?;
            },
            Value::Raw(buffer) => {
                file.write_all(&buffer)?;
            },
        }

        self.value()
    }

    // Get metadata ( ValueKind )
    #[inline]
    pub fn metadata(&self) -> Result<Metadata, io::Error> {
        unimplemented!()
    }

    #[inline]
    pub fn description(&self) -> Result<String, std::io::Error> {
        Err(io::Error::new(io::ErrorKind::Other, "Description not available on Linux"))
    }

    #[inline]
    pub fn iter(&self) -> Result<MibIter, io::Error> {
        MibIter::new(&self.path)
    }
}



impl FromStr for Mib {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let path = if s.starts_with(PATH_PREFIX) {
            if s.ends_with(PATH_PREFIX) {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            PathBuf::from(s)
        } else {
            PathBuf::from(PATH_PREFIX).join(s.replace(".", "/"))
        };
        
        // return absolute path, and ensure the path is exists.
        let path = path.canonicalize()?;

        debug_assert!(path.is_absolute());
        debug_assert!(path.exists());
        debug_assert!(path.starts_with(PATH_PREFIX));

        Ok(Self { path, })
    }
}

impl Default for Mib {
    fn default() -> Self {
        Self {
            path: PathBuf::from(ROOT_PATH)
        }
    }
}

#[derive(Debug)]
pub struct MibIter {
    dirs: Vec<ReadDir>,
}

impl MibIter {
    fn new(path: &Path) -> Result<Self, io::Error> {
        let root = Path::new(PATH_PREFIX);
        debug_assert!(root.is_dir());

        let mut dirs = Vec::new();
        dirs.push(root.read_dir()?);

        fn seek(dirs: &mut Vec<ReadDir>, stop_path: &Path) -> Result<(), io::Error> {
            if dirs.len() == 0 {
                return Ok(());
            }

            let idx = dirs.len() - 1;
            let dir = match dirs.get_mut(idx) {
                Some(dir) => dir,
                None => return Ok(()),
            };
            
            loop {
                let entry = dir.next();
                if entry.is_none() {
                    dirs.remove(idx);
                    return seek(dirs, stop_path);
                }

                let entry = entry.unwrap()?;
                let file_type = entry.file_type()?;
                let file_path = entry.path();
                
                if file_type.is_dir() {
                    dirs.push(file_path.read_dir()?);
                    if file_path == stop_path {
                        break;
                    }

                    return seek(dirs, stop_path);

                } else if file_type.is_file() {
                    // println!("Skip: {:?}", file_path);
                    if file_path == stop_path {
                        break;
                    }
                } else {
                    // TODO: symlink
                    unimplemented!()
                }
            }

            Ok(())
        }

        seek(&mut dirs, &path)?;
        
        Ok(MibIter {
            dirs: dirs,
        })
    }
}

impl Iterator for MibIter {
    type Item = Result<Mib, std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.dirs.len() == 0 {
            return None;
        }

        let idx = self.dirs.len() - 1;
        let dir = self.dirs.get_mut(idx).unwrap();

        match dir.next() {
            Some(Ok(entry)) => {
                let file_type = match entry.file_type() {
                    Ok(file_type) => file_type,
                    Err(e) => return Some(Err(e)),
                };
                let file_path = entry.path();
                
                if file_type.is_dir() {
                    match file_path.read_dir() {
                        Ok(sub_dir) => self.dirs.push(sub_dir),
                        Err(e) => return Some(Err(e)),
                    }
                    self.next()
                } else if file_type.is_file() {
                    let s = file_path.to_string_lossy().to_string();
                    Some(Mib::from_str(&s))
                } else {
                    // TODO: hanlde symlink
                    unimplemented!()
                }
            },
            Some(Err(e)) => return Some(Err(e)),
            None => {
                self.dirs.remove(idx);
                self.next()
            }
        }
    }
}

