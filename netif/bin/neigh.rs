
extern crate netif;

fn main(){
    let arp_table = netif::neighbor::V4::list().unwrap();
    println!("IP Address              Hardware Address     Netif");
    for item in arp_table.iter() {
        println!("{}", item);
    }
}