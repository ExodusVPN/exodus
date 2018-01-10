

use std::sync::atomic::{ATOMIC_BOOL_INIT, AtomicBool, Ordering};

use ctrlc;

static RUNNING: AtomicBool = ATOMIC_BOOL_INIT;


pub fn init() {
    RUNNING.store(true, Ordering::Relaxed);
    ctrlc::set_handler(move || {
        info!("graceful shutdown ...");
        RUNNING.store(false, Ordering::Relaxed);
    }).expect("Setting Ctrl-C handler failed.");
}

pub fn is_running() -> bool {
    RUNNING.load(Ordering::Relaxed)
}
