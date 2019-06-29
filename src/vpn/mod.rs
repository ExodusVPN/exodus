
mod client;
mod server;

pub use self::client::{VpnClientConfig, VpnClient};
pub use self::server::{VpnServerConfig, VpnServer};

pub const TAP_TOKEN: mio::Token    = mio::Token(10);
pub const TUN_TOKEN: mio::Token    = mio::Token(11);
pub const UDP_TOKEN: mio::Token    = mio::Token(12);


pub const DEFAULT_VPN_SERVER_TUNNEL_PORT: u16  = 9050;
pub const DEFAULT_VPN_SERVER_DHCP_PORT: u16    = 9051;

pub const DHCP_REQ_PACKET_SIGNATURE: [u8; 4] = [255, 255, 255, 200];
pub const DHCP_RES_PACKET_SIGNATURE: [u8; 4] = [255, 255, 255, 201];
// NOTE: 同时也是 macOS 系统里面 TUN 的 IPv4Packet 签名
pub const TUNNEL_PACKET_SIGNATURE: [u8; 4]   = [000, 000, 000, 002];
pub const BYE_PACKET_SIGNATURE: [u8; 4]      = [255, 255, 255, 255];


#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub enum InterfaceKind {
    Ethernet,
    // TAP Interface
    Internet,
}

