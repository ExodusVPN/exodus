#[macro_use(trace, debug, info, warn, error, log)] extern crate logging;

pub mod example_module {

    pub fn hello(){
        warn!("hello, 世界！");
    }
}

fn main () {
    logging::init(Some("debug")).unwrap();
    
    trace!("a trace example");
    debug!("deboogging");
    info!("such information");
    warn!("o_O");
    error!("boom");
    
    example_module::hello();

}