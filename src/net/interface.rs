extern crate ifaces;

fn main() {
    match ifaces::ifaces() {
        Ok(interfaces) => {
            for interface in interfaces.into_iter() {
                println!("Found interface: {:?}", interface)
            }
        },
        Err(_) => println!("Ooops ...")
    };
}