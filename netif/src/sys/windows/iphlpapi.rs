
use parent::*;

const MAX_ADAPTER_DESCRIPTION_LENGTH: usize = 128;
const MAX_ADAPTER_NAME_LENGTH: usize = 256;
const MAX_ADAPTER_ADDRESS_LENGTH: usize = 8;

const MAX_DHCPV6_DUID_LENGTH: usize = 130;
const MAX_DNS_SUFFIX_STRING_LENGTH: usize = 256;

// from IPTypes.h
#[repr(C)]
pub struct _IP_ADDRESS_STRING {
    pub String: [c_char; 4 * 4],
}

pub type IP_ADDRESS_STRING = _IP_ADDRESS_STRING;
pub type PIP_ADDRESS_STRING = *mut _IP_ADDRESS_STRING;
pub type IP_MASK_STRING = _IP_ADDRESS_STRING;
pub type PIP_MASK_STRING = *mut _IP_ADDRESS_STRING;


#[repr(C)]
pub struct _IP_ADDR_STRING {
    pub Next: *mut _IP_ADDR_STRING,
    pub IpAddress: IP_ADDRESS_STRING,
    pub IpMask: IP_MASK_STRING,
    pub Context: DWORD,
}

pub type IP_ADDR_STRING = _IP_ADDR_STRING;
pub type PIP_ADDR_STRING = *mut _IP_ADDR_STRING;

#[repr(C)]
pub struct _IP_ADAPTER_INFO {
    pub Next: *mut _IP_ADAPTER_INFO,
    pub ComboIndex: DWORD,
    pub AdapterName: [c_char; MAX_ADAPTER_NAME_LENGTH + 4],
    pub Description: [c_char; MAX_ADAPTER_DESCRIPTION_LENGTH + 4],
    pub AddressLength: UINT,
    pub Address: [BYTE; MAX_ADAPTER_ADDRESS_LENGTH],
    pub Index: DWORD,
    pub Type: UINT,
    pub DhcpEnabled: UINT,
    pub CurrentIpAddress: PIP_ADDR_STRING,
    pub IpAddressList: IP_ADDR_STRING,
    pub GatewayList: IP_ADDR_STRING,
    pub DhcpServer: IP_ADDR_STRING,
    pub HaveWins: BOOL,
    pub PrimaryWinsServer: IP_ADDR_STRING,
    pub SecondaryWinsServer: IP_ADDR_STRING,
    pub LeaseObtained: time_t,
    pub LeaseExpires: time_t,
}

pub type IP_ADAPTER_INFO = _IP_ADAPTER_INFO;
pub type PIP_ADAPTER_INFO = *mut _IP_ADAPTER_INFO;

#[repr(C)]
pub enum IP_PREFIX_ORIGIN {
    IpPrefixOriginOther = 0,
    IpPrefixOriginManual,
    IpPrefixOriginWellKnown,
    IpPrefixOriginDhcp,
    IpPrefixOriginRouterAdvertisement,
    IpPrefixOriginUnchanged = 16,
}

#[repr(C)]
pub enum IP_SUFFIX_ORIGIN {
    IpSuffixOriginOther = 0,
    IpSuffixOriginManual,
    IpSuffixOriginWellKnown,
    IpSuffixOriginDhcp,
    IpSuffixOriginLinkLayerAddress,
    IpSuffixOriginRandom,
    IpSuffixOriginUnchanged = 16,
}

#[repr(C)]
pub struct _IP_ADAPTER_UNICAST_ADDRESS {
    pub Length: ULONG,
    pub Flags: DWORD,
    pub Next: *mut _IP_ADAPTER_UNICAST_ADDRESS,
    pub Address: SOCKET_ADDRESS,
    pub PrefixOrigin: IP_PREFIX_ORIGIN,
    pub SuffixOrigin: IP_SUFFIX_ORIGIN,
    pub DadState: IP_DAD_STATE,
    pub ValidLifetime: ULONG,
    pub PreferredLifetime: ULONG,
    pub LeaseLifetime: ULONG,
    pub OnLinkPrefixLength: UINT8,
}

pub type IP_ADAPTER_UNICAST_ADDRESS = _IP_ADAPTER_UNICAST_ADDRESS;
pub type PIP_ADAPTER_UNICAST_ADDRESS = *mut _IP_ADAPTER_UNICAST_ADDRESS;

#[repr(C)]
pub struct _IP_ADAPTER_ANYCAST_ADDRESS {
    pub Length: ULONG,
    pub Flags: DWORD,
    pub Next: *mut _IP_ADAPTER_ANYCAST_ADDRESS,
    pub Address: SOCKET_ADDRESS,
}

pub type IP_ADAPTER_ANYCAST_ADDRESS = _IP_ADAPTER_ANYCAST_ADDRESS;
pub type PIP_ADAPTER_ANYCAST_ADDRESS = *mut _IP_ADAPTER_ANYCAST_ADDRESS;

#[repr(C)]
pub struct _IP_ADAPTER_MULTICAST_ADDRESS {
    pub Length: ULONG,
    pub Flags: DWORD,
    pub Next: *mut _IP_ADAPTER_MULTICAST_ADDRESS,
    pub Address: SOCKET_ADDRESS,
}

pub type IP_ADAPTER_MULTICAST_ADDRESS = _IP_ADAPTER_MULTICAST_ADDRESS;
pub type PIP_ADAPTER_MULTICAST_ADDRESS = *mut _IP_ADAPTER_MULTICAST_ADDRESS;

#[repr(C)]
pub struct _IP_ADAPTER_DNS_SERVER_ADDRESS {
    pub Length: ULONG,
    pub Flags: DWORD,
    pub Next: *mut _IP_ADAPTER_DNS_SERVER_ADDRESS,
    pub Address: SOCKET_ADDRESS,
}

pub type IP_ADAPTER_DNS_SERVER_ADDRESS = _IP_ADAPTER_DNS_SERVER_ADDRESS;
pub type PIP_ADAPTER_DNS_SERVER_ADDRESS = *mut _IP_ADAPTER_DNS_SERVER_ADDRESS;

#[repr(C)]
pub struct _IP_ADAPTER_DNS_SUFFIX {
    pub Next: *mut _IP_ADAPTER_DNS_SUFFIX,
    pub String: [WCHAR; MAX_DNS_SUFFIX_STRING_LENGTH],
}

pub type IP_ADAPTER_DNS_SUFFIX = _IP_ADAPTER_DNS_SUFFIX;
pub type PIP_ADAPTER_DNS_SUFFIX = *mut _IP_ADAPTER_DNS_SUFFIX;

#[repr(C)]
pub struct _IP_ADAPTER_ADDRESSES {
    pub Length: ULONG,
    pub IfIndex: DWORD,
    pub Next: *mut _IP_ADAPTER_ADDRESSES,
    pub AdapterName: PCHAR,
    pub FirstUnicastAddress: PIP_ADAPTER_UNICAST_ADDRESS,
    pub FirstAnycastAddress: PIP_ADAPTER_ANYCAST_ADDRESS,
    pub FirstMulticastAddress: PIP_ADAPTER_MULTICAST_ADDRESS,
    pub FirstDnsServerAddress: PIP_ADAPTER_DNS_SERVER_ADDRESS,
    pub DnsSuffix: PWCHAR,
    pub Description: PWCHAR,
    pub FriendlyName: PWCHAR,
    pub PhysicalAddress: [BYTE; MAX_ADAPTER_ADDRESS_LENGTH],
    pub PhysicalAddressLength: DWORD,
    pub Flags: DWORD,
    pub Mtu: DWORD,
    pub IfType: DWORD,
    pub OperStatus: IF_OPER_STATUS,
    pub Ipv6IfIndex: DWORD,
    pub ZoneIndices: [DWORD; 16],
    pub FirstPrefix: PIP_ADAPTER_PREFIX,
    pub TransmitLinkSpeed: ULONG64,
    pub ReceiveLinkSpeed: ULONG64,
    pub FirstWinsServerAddress: PIP_ADAPTER_WINS_SERVER_ADDRESS_LH,
    pub FirstGatewayAddress: PIP_ADAPTER_GATEWAY_ADDRESS_LH,
    pub Ipv4Metric: ULONG,
    pub Ipv6Metric: ULONG,
    pub Luid: IF_LUID,
    pub Dhcpv4Server: SOCKET_ADDRESS,
    pub CompartmentId: NET_IF_COMPARTMENT_ID,
    pub NetworkGuid: NET_IF_NETWORK_GUID,
    pub ConnectionType: NET_IF_CONNECTION_TYPE,
    pub TunnelType: TUNNEL_TYPE,
    pub Dhcpv6Server: SOCKET_ADDRESS,
    pub Dhcpv6ClientDuid: [BYTE; MAX_DHCPV6_DUID_LENGTH],
    pub Dhcpv6ClientDuidLength: ULONG,
    pub Dhcpv6Iaid: ULONG,
    pub FirstDnsSuffix: PIP_ADAPTER_DNS_SUFFIX,
}

pub type IP_ADAPTER_ADDRESSES = _IP_ADAPTER_ADDRESSES;
pub type PIP_ADAPTER_ADDRESSES = *mut _IP_ADAPTER_ADDRESSES;


// #[repr(C)]
// pub struct IPAddrS_un_b {
//     pub s_b1: c_uchar,
//     pub s_b2: c_uchar,
//     pub s_b3: c_uchar,
//     pub s_b4: c_uchar,
// }

// #[repr(C)]
// pub struct IPAddrS_un_w {
//     pub s_w1: c_ushort,
//     pub s_w2: c_ushort,
// }

// #[repr(C)]
// pub union IPAddrS_un {
//     // The IPv4 address of the host formatted as four u_chars.
//     pub S_un_b: IPAddrS_un_b,
//     // The IPv4 address of the host formatted as two u_shorts.
//     pub S_un_w: IPAddrS_un_w,
//     // Address of the host formatted as a u_long.
//     pub S_addr: c_ulong
// }

// #[repr(C)]
// pub struct IPAddr {
//     pub S_un: IPAddrS_un
// }

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa366055(v=vs.85).aspx
pub type IPAddr = in_addr;
pub type sockaddr = SOCKADDR;

// DWORD
#[repr(C)]
pub enum MIB_IPFORWARD_YPE {
    MIB_IPROUTE_TYPE_OTHER = 1DWORD,
    MIB_IPROUTE_TYPE_INVALID = 2,
    MIB_IPROUTE_TYPE_DIRECT = 3,
    MIB_IPROUTE_TYPE_INDIRECT = 4
}

// DWORD
#[repr(C)]
pub enum MIB_IPPROTO {
    MIB_IPPROTO_OTHER = 1DWORD,
    MIB_IPPROTO_LOCAL = 2,
    MIB_IPPROTO_NETMGMT = 3,
    MIB_IPPROTO_ICMP = 4,
    MIB_IPPROTO_EGP = 5,
    MIB_IPPROTO_GGP = 6,
    MIB_IPPROTO_HELLO = 7,
    MIB_IPPROTO_RIP = 8,
    MIB_IPPROTO_IS_IS = 9,
    MIB_IPPROTO_ES_IS = 10,
    MIB_IPPROTO_CISCO = 11,
    MIB_IPPROTO_BBN = 12,
    MIB_IPPROTO_OSPF = 13,
    MIB_IPPROTO_BGP = 14,
    MIB_IPPROTO_NT_AUTOSTATIC = 10002,
    MIB_IPPROTO_NT_STATIC = 10006,
    MIB_IPPROTO_NT_STATIC_NON_DOD = 10007,
}

#[repr(C)]
pub struct _MIB_IPFORWARDROW {
    pub dwForwardDest: DWORD,
    pub dwForwardMask: DWORD,
    pub dwForwardPolicy: DWORD,
    pub dwForwardNextHop: DWORD,
    pub dwForwardIfIndex: DWORD,
    pub dwForwardType: MIB_IPFORWARD_YPE,
    pub dwForwardProto: MIB_IPPROTO,
    pub dwForwardAge: DWORD,
    pub dwForwardNextHopAS: DWORD,
    pub dwForwardMetric1: DWORD,
    pub dwForwardMetric2: DWORD,
    pub dwForwardMetric3: DWORD,
    pub dwForwardMetric4: DWORD,
    pub dwForwardMetric5: DWORD,
}

pub type MIB_IPFORWARDROW = _MIB_IPFORWARDROW;
pub type PMIB_IPFORWARDROW = *mut _MIB_IPFORWARDROW;

typedef struct _MIB_IPFORWARD_ROW2 {
  NET_LUID          InterfaceLuid;
  NET_IFINDEX       InterfaceIndex;
  IP_ADDRESS_PREFIX DestinationPrefix;
  SOCKADDR_INET      NextHop;
  UCHAR             SitePrefixLength;
  ULONG             ValidLifetime;
  ULONG             PreferredLifetime;
  ULONG             Metric;
  NL_ROUTE_PROTOCOL Protocol;
  BOOLEAN           Loopback;
  BOOLEAN           AutoconfigureAddress;
  BOOLEAN           Publish;
  BOOLEAN           Immortal;
  ULONG             Age;
  NL_ROUTE_ORIGIN   Origin;
} MIB_IPFORWARD_ROW2, *PMIB_IPFORWARD_ROW2;


// https://msdn.microsoft.com/en-us/library/windows/desktop/aa366320(v=vs.85).aspx
// https://github.com/Alexpux/mingw-w64/blob/master/mingw-w64-headers/include/ifdef.h#L96
#[repr(C)]
pub struct _NET_LUID_Info {
    pub Reserved: ULONG64,     // :24 , This field is reserved.
    pub NetLuidIndex: ULONG64, // :24 , The network interface LUID index.
    pub IfType: ULONG64,       // :16 , The interface type as defined by the Internet Assigned Names Authority (IANA). Possible values for the interface type are listed in the Ipifcons.h include file.
                               //       The table below lists common values for the interface type although many other values are possible. 
}

pub const IF_TYPE_OTHER: ULONG64 = 1;              // Some other type of network interface.
pub const IF_TYPE_ETHERNET_CSMACD: ULONG64 = 6;    // An Ethernet network interface.
pub const IF_TYPE_ISO88025_TOKENRING: ULONG64 = 9; // A token ring network interface.
pub const IF_TYPE_PPP: ULONG64 = 23;               // A PPP network interface.
pub const IF_TYPE_SOFTWARE_LOOPBACK: ULONG64 = 24; // A software loopback network interface.
pub const IF_TYPE_ATM: ULONG64 = 37;               // An ATM network interface.
pub const IF_TYPE_IEEE80211: ULONG64 = 71;         // An IEEE 802.11 wireless network interface.
pub const IF_TYPE_TUNNEL: ULONG64 = 131;           // A tunnel type encapsulation network interface.
pub const IF_TYPE_IEEE1394: ULONG64 = 144;         // An IEEE 1394 (Firewire) high performance serial bus network interface.

#[repr(C)]
pub union _NET_LUID {
    pub Value: ULONG64,       // A 64-bit value that represents the LUID.
    pub Info: _NET_LUID_Info, // A named union containing the component fields in the 64-bit LUID Value member.
}

pub type NET_LUID = _NET_LUID;
pub type PNET_LUID = *mut NET_LUID;

pub type NET_IFINDEX = ULONG;
pub type PNET_IFINDEX = *mut NET_IFINDEX;

#[repr(C)]
pub struct SOCKADDR_IN6 {
    pub sin6_family: c_short,
    pub sin6_port: c_ushort,
    pub sin6_flowinfo: c_ulong,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: c_ulong,
}

// The SOCKADDR_INET union contains an IPv4, an IPv6 address, or an address family.
#[repr(C)]
pub union _SOCKADDR_INET {
    pub Ipv4: SOCKADDR_IN,
    pub Ipv6: SOCKADDR_IN6,
    pub si_family: ADDRESS_FAMILY,
}

pub type SOCKADDR_INET = _SOCKADDR_INET;
pub type PSOCKADDR_INET = *mut SOCKADDR_INET;

#[repr(C)]
pub struct _IP_ADDRESS_PREFIX {
    pub Prefix: SOCKADDR_INET,
    pub PrefixLength: UINT8,
}
pub type IP_ADDRESS_PREFIX = _IP_ADDRESS_PREFIX;
pub type PIP_ADDRESS_PREFIX = *mut IP_ADDRESS_PREFIX;

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa814494(v=vs.85).aspx
#[repr(C)]
pub enum NL_ROUTE_PROTOCOL {
    MIB_IPPROTO_OTHER = 1,    // The routing mechanism was not specified. 
    MIB_IPPROTO_LOCAL = 2,    // A local interface.
    MIB_IPPROTO_NETMGMT = 3,
    MIB_IPPROTO_ICMP = 4,
    MIB_IPPROTO_EGP = 5,
    MIB_IPPROTO_GGP = 6,
    MIB_IPPROTO_HELLO = 7,
    MIB_IPPROTO_RIP = 8,
    MIB_IPPROTO_IS_IS = 9,
    MIB_IPPROTO_ES_IS = 10,
    MIB_IPPROTO_CISCO = 11,
    MIB_IPPROTO_BBN = 12,
    MIB_IPPROTO_OSPF = 13,
    MIB_IPPROTO_BGP = 14,
    MIB_IPPROTO_NT_AUTOSTATIC = 10002,
    MIB_IPPROTO_NT_STATIC = 10006,
    MIB_IPPROTO_NT_STATIC_NON_DOD = 10007,
}

#[repr(C)]
pub enum NL_ROUTE_ORIGIN {
    NlroManual = 0,              // A result of manual configuration. 
    NlroWellKnown = 1,           // A well-known route.
    NlroDHCP = 2,                // A result of DHCP configuration.
    NlroRouterAdvertisement = 3, // The result of router advertisement.
    Nlro6to4 = 4,                // A result of 6to4 tunneling.
}

#[repr(C)]
pub struct _MIB_IPFORWARD_ROW2 {
    pub InterfaceLuid: NET_LUID,
    pub InterfaceIndex: NET_IFINDEX,
    pub DestinationPrefix: IP_ADDRESS_PREFIX,
    pub NextHop: SOCKADDR_INET,
    pub SitePrefixLength: UCHAR,
    pub ValidLifetime: ULONG,
    pub PreferredLifetime: ULONG,
    pub Metric: ULONG,
    pub Protocol: NL_ROUTE_PROTOCOL,
    pub Loopback: BOOLEAN,
    pub AutoconfigureAddress: BOOLEAN,
    pub Publish: BOOLEAN,
    pub Immortal: BOOLEAN,
    pub Age: ULONG,
    pub Origin: NL_ROUTE_ORIGIN,
}

pub type MIB_IPFORWARD_ROW2 = _MIB_IPFORWARD_ROW2;
pub type PMIB_IPFORWARD_ROW2 = *mut MIB_IPFORWARD_ROW2;

// NO_ERROR or ERROR_INVALID_PARAMETER / ERROR_FILE_NOT_FOUND / ERROR_NOT_SUPPORTED / Other
pub type NETIOAPI_API = DWORD;


#[link(name = "iphlpapi")]
extern "system" {
    // from IPHlpApi.h
    pub fn GetAdaptersInfo(pAdapterInfo: PIP_ADAPTER_INFO, pOutBufLen: PULONG) -> DWORD;
    pub fn GetAdaptersAddresses(Family: ULONG,
                                Flags: ULONG,
                                Reserved: PVOID,
                                AdapterAddresses: PIP_ADAPTER_ADDRESSES,
                                SizePointer: PULONG)
        -> ULONG;
    pub fn GetBestInterface(dwDestAddr: IPAddr, pdwBestIfIndex: PDWORD) -> DWORD;
    pub fn GetBestInterfaceEx(pDestAddr: *mut sockaddr, pdwBestIfIndex: PDWORD) -> DWORD;
    pub fn GetBestRoute(dwDestAddr: DWORD, dwSourceAddr: DWORD, pBestRoute: PMIB_IPFORWARDROW) -> DWORD;
    pub fn GetBestRoute2(InterfaceLuid: *mut NET_LUID,
                         InterfaceIndex: NET_IFINDEX,
                         SourceAddress: *const SOCKADDR_INET,
                         DestinationAddress: *const SOCKADDR_INET,
                         AddressSortOptions: ULONG,
                         BestRoute: PMIB_IPFORWARD_ROW2,
                         BestSourceAddress: *mut SOCKADDR_INET) -> NETIOAPI_API;

}