#![feature(macro_reexport)]


#[macro_reexport(trace, log, info, warn, error, debug)]
extern crate log;
extern crate env_logger;
extern crate time;
extern crate ansi_term;


use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering, ATOMIC_USIZE_INIT};

static MAX_MODULE_WIDTH: AtomicUsize = ATOMIC_USIZE_INIT;
struct Level(log::LogLevel);


impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            log::LogLevel::Trace => ansi_term::Color::Purple.paint("TRACE"),
            log::LogLevel::Debug => ansi_term::Color::Blue.paint("DEBUG"),
            log::LogLevel::Info  => ansi_term::Color::Green.paint(" INFO"),
            log::LogLevel::Warn  => ansi_term::Color::Yellow.paint(" WARN"),
            log::LogLevel::Error => ansi_term::Color::Red.paint("ERROR")
        }.fmt(f)
    }
}


pub fn init(level: Option<&str>) -> Result<(), log::SetLoggerError> {
    let mut builder = env_logger::LogBuilder::new();

    builder.format(|record| {
        let mut module_path = record.location().module_path().to_string();
        let max_width = MAX_MODULE_WIDTH.load(Ordering::Relaxed);
        if max_width > module_path.len() {
            let diff = max_width - module_path.len();
            module_path.extend(::std::iter::repeat(' ').take(diff));
        } else {
            MAX_MODULE_WIDTH.store(module_path.len(), Ordering::Relaxed);
        }
        format!("[{} {}] {} {}",
                time::now().strftime("%Y-%m-%d %H:%M:%S.%f").unwrap(),
                Level(record.level()),
                ansi_term::Style::new().bold().paint(module_path),
                record.args())
    });

    if let Ok(s) = ::std::env::var("RUST_LOG") {
        builder.parse(&s);
    } else if level.is_some() {
        builder.parse(level.unwrap());
    }
    builder.init()
}

