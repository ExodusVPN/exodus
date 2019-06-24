use ctrlc;

use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(true);

pub fn init() {
    ctrlc::set_handler(move || {
        info!("graceful shutdown ...");
        RUNNING.store(false, Ordering::Relaxed);
    }).expect("Setting Ctrl-C handler failed.");
}

pub fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}
