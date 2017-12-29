extern crate netif;

/*
macOS:
    $ netstat -rn
    $ cargo run --bin route
*/

fn main(){
    let routing_table = netif::route::list().unwrap();
    println!("{:40} {:40} {:55} {}", "Destination", "Gateway", "Flags", "Netif");
    for item in routing_table.iter() {
        println!("{}", item);
    }
}