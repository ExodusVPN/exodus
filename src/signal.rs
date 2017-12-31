

use std::sync::atomic::{ATOMIC_BOOL_INIT, AtomicBool, Ordering};

use ctrlc;

static RUNNING: AtomicBool = ATOMIC_BOOL_INIT;


pub fn init() {
    RUNNING.store(true, Ordering::SeqCst);
    ctrlc::set_handler(move || { RUNNING.store(false, Ordering::SeqCst); })
        .expect("Error setting Ctrl-C handler");
}

pub fn is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}
