
macro_rules! res2opt {
    ($expression:expr) => (
        match $expression {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        }
    )
}