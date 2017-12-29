extern crate netif;

fn main() {
    let ifaces = netif::interface::interfaces();
    for x in ifaces{
        println!("{}", x);
    }
}