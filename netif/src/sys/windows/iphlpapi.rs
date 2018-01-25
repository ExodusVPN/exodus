
use parent::*;

// from IPHlpApi.h
pub const MAX_ADAPTER_DESCRIPTION_LENGTH: usize = 128;
pub const MAX_ADAPTER_NAME: usize = 128;
pub const MAX_ADAPTER_NAME_LENGTH: usize = 256;
pub const MAX_ADAPTER_ADDRESS_LENGTH: usize = 8;

pub const MAX_DHCPV6_DUID_LENGTH: usize = 130;
pub const MAX_DNS_SUFFIX_STRING_LENGTH: usize = 256;

pub const MAX_INTERFACE_NAME_LEN: usize = 256;
pub const MAXLEN_PHYSADDR: usize = 8;
pub const MAXLEN_IFDESCR: usize = 256;

// from ifdef.h
pub const IF_MAX_STRING_SIZE: usize = 256;
pub const IF_MAX_PHYS_ADDRESS_LENGTH: usize = 32;

pub const ANY_SIZE: usize = 1;


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
pub struct _IP_ADAPTER_PREFIX {
    pub Length: ULONG,
    pub Flags: DWORD,
    pub Next: *mut _IP_ADAPTER_PREFIX,
    pub Address: SOCKET_ADDRESS,
    pub PrefixLength: ULONG,
}

pub type IP_ADAPTER_PREFIX = _IP_ADAPTER_PREFIX;
pub type PIP_ADAPTER_PREFIX = *mut _IP_ADAPTER_PREFIX;

#[repr(C)]
pub struct _IP_ADAPTER_WINS_SERVER_ADDRESS_LH {
    pub Length: ULONG,
    pub Reserved: DWORD,
    pub Next: *mut _IP_ADAPTER_WINS_SERVER_ADDRESS_LH,
    pub Address: SOCKET_ADDRESS,
}

pub type IP_ADAPTER_WINS_SERVER_ADDRESS_LH = _IP_ADAPTER_WINS_SERVER_ADDRESS_LH;
pub type PIP_ADAPTER_WINS_SERVER_ADDRESS_LH = *mut _IP_ADAPTER_WINS_SERVER_ADDRESS_LH;
pub type IP_ADAPTER_WINS_SERVER_ADDRESS = _IP_ADAPTER_WINS_SERVER_ADDRESS_LH;
pub type PIP_ADAPTER_WINS_SERVER_ADDRESS = *mut _IP_ADAPTER_WINS_SERVER_ADDRESS_LH;

#[repr(C)]
pub struct _IP_ADAPTER_GATEWAY_ADDRESS_LH {
    pub Length: ULONG,
    pub Reserved: DWORD,
    pub Next: *mut _IP_ADAPTER_GATEWAY_ADDRESS_LH,
    pub Address: SOCKET_ADDRESS,
}

pub type IP_ADAPTER_GATEWAY_ADDRESS_LH = _IP_ADAPTER_GATEWAY_ADDRESS_LH;
pub type PIP_ADAPTER_GATEWAY_ADDRESS_LH = *mut _IP_ADAPTER_GATEWAY_ADDRESS_LH;
pub type IP_ADAPTER_GATEWAY_ADDRESS = _IP_ADAPTER_GATEWAY_ADDRESS_LH;
pub type PIP_ADAPTER_GATEWAY_ADDRESS = *mut _IP_ADAPTER_GATEWAY_ADDRESS_LH;

/// The IP_UNIDIRECTIONAL_ADAPTER_ADDRESS structure stores
/// the IPv4 addresses associated with a unidirectional adapter.
#[repr(C)]
pub struct _IP_UNIDIRECTIONAL_ADAPTER_ADDRESS {
    /// The number of IPv4 addresses pointed to by the Address member.
    pub NumAdapters: ULONG,
    /// An array of variables of type IPAddr. 
    /// Each element of the array specifies an IPv4 address 
    /// associated with this unidirectional adapter.
    pub Address: [IPAddr; 1],
}

pub type IP_UNIDIRECTIONAL_ADAPTER_ADDRESS = _IP_UNIDIRECTIONAL_ADAPTER_ADDRESS;
pub type PIP_UNIDIRECTIONAL_ADAPTER_ADDRESS = *mut _IP_UNIDIRECTIONAL_ADAPTER_ADDRESS;

#[repr(C)]
pub struct _IP_PER_ADAPTER_INFO {
    /// Specifies whether IP address auto-configuration (APIPA) 
    /// is enabled on this adapter. See Remarks.
    pub AutoconfigEnabled: UINT,
    /// Specifies whether this adapter's IP address is 
    /// currently auto-configured by APIPA.
    pub AutoconfigActive: UINT,
    /// Reserved. Use the DnsServerList member to obtain 
    /// the DNS servers for the local computer.
    pub CurrentDnsServer: PIP_ADDR_STRING,
    /// A linked list of IP_ADDR_STRING structures that specify 
    /// the set of DNS servers used by the local computer.
    pub DnsServerList: IP_ADDR_STRING,
}

pub type IP_PER_ADAPTER_INFO = _IP_PER_ADAPTER_INFO;
pub type PIP_PER_ADAPTER_INFO = *mut _IP_PER_ADAPTER_INFO;


#[repr(C)]
pub enum IF_OPER_STATUS {
    IfOperStatusUp = 1,
    IfOperStatusDown,
    IfOperStatusTesting,
    IfOperStatusUnknown,
    IfOperStatusDormant,
    IfOperStatusNotPresent,
    IfOperStatusLowerLayerDown,
}

pub type NET_IF_COMPARTMENT_ID = UINT32;
pub type PNET_IF_COMPARTMENT_ID = *mut UINT32;
pub type NET_IF_NETWORK_GUID = GUID;
pub type PNET_IF_NETWORK_GUID = *mut GUID;

#[repr(C)]
pub enum _NET_IF_CONNECTION_TYPE {
    NET_IF_CONNECTION_DEDICATED = 1,
    NET_IF_CONNECTION_PASSIVE = 2,
    NET_IF_CONNECTION_DEMAND = 3,
    NET_IF_CONNECTION_MAXIMUM = 4,
}

pub type NET_IF_CONNECTION_TYPE = _NET_IF_CONNECTION_TYPE;
pub type PNET_IF_CONNECTION_TYPE = *mut _NET_IF_CONNECTION_TYPE;

#[repr(C)]
pub enum TUNNEL_TYPE {
    TUNNEL_TYPE_NONE = 0,
    TUNNEL_TYPE_OTHER = 1,
    TUNNEL_TYPE_DIRECT = 2,
    TUNNEL_TYPE_6TO4 = 11,
    TUNNEL_TYPE_ISATAP = 13,
    TUNNEL_TYPE_TEREDO = 14,
    TUNNEL_TYPE_IPHTTPS = 15,
}

pub type PTUNNEL_TYPE = *mut TUNNEL_TYPE;

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

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa366055(v=vs.85).aspx
pub type IPAddr = in_addr;
pub type IPMask = ULONG;
pub type IP_STATUS = ULONG;
pub type sockaddr = SOCKADDR;


#[repr(C)]
pub enum MIB_IPFORWARD_YPE {
    // Some other type not specified in RFC 1354.
    MIB_IPROUTE_TYPE_OTHER    = 1u32, // DWORD == u32
    // An invalid route. This value can result from 
    // a route added by an ICMP redirect.
    MIB_IPROUTE_TYPE_INVALID  = 2,
    // A local route where the next hop is 
    // the final destination (a local interface).
    MIB_IPROUTE_TYPE_DIRECT   = 3,
    // The remote route where the next hop is not 
    // the final destination (a remote destination).
    MIB_IPROUTE_TYPE_INDIRECT = 4
}

#[repr(C)]
pub enum MIB_IPPROTO {
    // Some other protocol not specified in RFC 1354.
    MIB_IPPROTO_OTHER = 1u32,      // DWORD == u32
    // A local interface.
    MIB_IPPROTO_LOCAL = 2,
    // A static route. This value is used to identify route information for 
    // IP routing set through network management such as the Dynamic Host
    // Configuration Protocol (DCHP), the Simple Network Management Protocol (SNMP),
    // or by calls to the CreateIpForwardEntry, 
    // DeleteIpForwardEntry, or SetIpForwardEntry functions.
    MIB_IPPROTO_NETMGMT = 3,
    // The result of ICMP redirect.
    MIB_IPPROTO_ICMP = 4,
    // The Exterior Gateway Protocol (EGP), a dynamic routing protocol.
    MIB_IPPROTO_EGP = 5,
    // The Gateway-to-Gateway Protocol (GGP), a dynamic routing protocol.
    MIB_IPPROTO_GGP = 6,
    // The Hellospeak protocol, a dynamic routing protocol. This is a historical 
    // entry no longer in use and was an early routing protocol used by the original
    // ARPANET routers that ran special software called the Fuzzball routing protocol,
    // sometimes called Hellospeak, as described in RFC 891 and RFC 1305. For more information,
    // see http://www.ietf.org/rfc/rfc891.txt and http://www.ietf.org/rfc/rfc1305.txt. 
    MIB_IPPROTO_HELLO = 7,
    // The Berkeley Routing Information Protocol (RIP) or RIP-II, 
    // a dynamic routing protocol.
    MIB_IPPROTO_RIP = 8,
    // The Intermediate System-to-Intermediate System (IS-IS) protocol, 
    // a dynamic routing protocol. The IS-IS protocol was developed for 
    // use in the Open Systems Interconnection (OSI) protocol suite.
    MIB_IPPROTO_IS_IS = 9,
    // The End System-to-Intermediate System (ES-IS) protocol, 
    // a dynamic routing protocol. The ES-IS protocol was developed for 
    // use in the Open Systems Interconnection (OSI) protocol suite.
    MIB_IPPROTO_ES_IS = 10,
    // The Cisco Interior Gateway Routing Protocol (IGRP), 
    // a dynamic routing protocol.
    MIB_IPPROTO_CISCO = 11,
    // The Bolt, Beranek, and Newman (BBN) Interior Gateway Protocol (IGP) that 
    // used the Shortest Path First (SPF) algorithm. 
    // This was an early dynamic routing protocol.
    MIB_IPPROTO_BBN = 12,
    // The Open Shortest Path First (OSPF) protocol, 
    // a dynamic routing protocol.
    MIB_IPPROTO_OSPF = 13,
    // The Border Gateway Protocol (BGP), a dynamic routing protocol.
    MIB_IPPROTO_BGP = 14,
    // A Windows specific entry added originally by a routing protocol,
    // but which is now static.
    MIB_IPPROTO_NT_AUTOSTATIC = 10002,
    // A Windows specific entry added as a static route from 
    // the routing user interface or a routing command. 
    MIB_IPPROTO_NT_STATIC = 10006,
    // A Windows specific entry added as a static route from 
    // the routing user interface or a routing command, 
    // except these routes do not cause Dial On Demand (DOD).
    MIB_IPPROTO_NT_STATIC_NON_DOD = 10007,
}

// https://msdn.microsoft.com/en-us/library/windows/desktop/aa366850(v=vs.85).aspx
/// The MIB_IPFORWARDROW structure contains information that describes an IPv4 network route. 
#[repr(C)]
pub struct _MIB_IPFORWARDROW {
    pub dwForwardDest: DWORD,
    pub dwForwardMask: DWORD,
    pub dwForwardPolicy: DWORD,
    pub dwForwardNextHop: DWORD,
    pub dwForwardIfIndex: DWORD,
    pub dwForwardType: MIB_IPFORWARD_YPE, // DWORD
    pub dwForwardProto: MIB_IPPROTO,      // DWORD
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

#[repr(C)]
pub struct _NET_LUID_Info(pub u64);

impl _NET_LUID_Info {
    // 24 bits , This field is reserved.
    #[inline]
    pub fn Reserved(&self) -> ULONG64 {
        self.0 >> 40
    }

    // 24 bits , The network interface LUID index.
    #[inline]
    pub fn NetLuidIndex(&self) -> ULONG64 {
        ( self.0 >> 16 ) & 0b_00000000_00000000_00000000_11111111_11111111_11111111
    }

    // 16 bits
    // The interface type as defined by the Internet Assigned Names Authority (IANA). 
    // Possible values for the interface type are listed in the Ipifcons.h include file.
    // The table below lists common values for the interface type although many other values 
    // are possible. 
    #[inline]
    pub fn IfType(&self) -> ULONG64 {
        self.0 & 0b_00000000_00000000_00000000_00000000_00000000_00000000_11111111_11111111
    }
}

// ULONG64
#[repr(C)]
pub enum IF_TYPE {
    // Some other type of network interface.
    IF_TYPE_OTHER = 1,
    // An Ethernet network interface.
    IF_TYPE_ETHERNET_CSMACD = 6,
    // A token ring network interface.
    IF_TYPE_ISO88025_TOKENRING = 9,
    // A PPP network interface.
    IF_TYPE_PPP = 23,
    // A software loopback network interface.
    IF_TYPE_SOFTWARE_LOOPBACK = 24,
    // An ATM network interface.
    IF_TYPE_ATM = 37,
    // An IEEE 802.11 wireless network interface.
    IF_TYPE_IEEE80211 = 71,
    // A tunnel type encapsulation network interface.
    IF_TYPE_TUNNEL = 131,
    // An IEEE 1394 (Firewire) high performance serial bus network interface.
    IF_TYPE_IEEE1394 = 144,

    // Note: interface type is supported on Windows 7, Windows Server 2008 R2, and later.
    // A mobile broadband interface for WiMax devices.
    IF_TYPE_IEEE80216_WMAN = 237,
    // A mobile broadband interface for GSM-based devices.
    IF_TYPE_WWANPP = 243,
    // A mobile broadband interface for CDMA-based devices.
    IF_TYPE_WWANPP2 = 244,
}

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

// The SOCKADDR_INET union contains an IPv4, 
// an IPv6 address, or an address family.
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
    // The routing mechanism was not specified. 
    MIB_IPPROTO_OTHER = 1i32,
    // A local interface.
    MIB_IPPROTO_LOCAL = 2,
    // A static route. This value is used to identify route information for 
    // IP routing set through network management such as the 
    // Dynamic Host Configuration Protocol (DCHP), 
    // the Simple Network Management Protocol (SNMP), 
    // or by calls to the CreateIpForwardEntry2, DeleteIpForwardEntry2, 
    // or SetIpForwardEntry2 functions.
    MIB_IPPROTO_NETMGMT = 3,
    // The result of an ICMP redirect.
    MIB_IPPROTO_ICMP = 4,
    // The Exterior Gateway Protocol (EGP), a dynamic routing protocol.
    MIB_IPPROTO_EGP = 5,
    // The Gateway-to-Gateway Protocol (GGP), a dynamic routing protocol.
    MIB_IPPROTO_GGP = 6,
    // The Hellospeak protocol, a dynamic routing protocol. 
    // This is a historical entry no longer in use and was an early 
    // routing protocol used by the original ARPANET routers that ran special 
    // software called the Fuzzball routing protocol, sometimes called Hellospeak, 
    // as described in RFC 891 and RFC 1305. 
    // For more information,
    // see http://www.ietf.org/rfc/rfc891.txt and http://www.ietf.org/rfc/rfc1305.txt. 
    MIB_IPPROTO_HELLO = 7,
    // The Berkeley Routing Information Protocol (RIP) or RIP-II,
    // a dynamic routing protocol.
    MIB_IPPROTO_RIP = 8,
    // The Intermediate System-to-Intermediate System (IS-IS) protocol, 
    // a dynamic routing protocol. The IS-IS protocol was developed for 
    // use in the Open Systems Interconnection (OSI) protocol suite. 
    MIB_IPPROTO_IS_IS = 9,
    // The End System-to-Intermediate System (ES-IS) protocol, 
    // a dynamic routing protocol. The ES-IS protocol was developed 
    // for use in the Open Systems Interconnection (OSI) protocol suite. 
    MIB_IPPROTO_ES_IS = 10,
    // The Cisco Interior Gateway Routing Protocol (IGRP),
    // a dynamic routing protocol.
    MIB_IPPROTO_CISCO = 11,
    // The Bolt, Beranek, and Newman (BBN) Interior Gateway Protocol (IGP) that 
    // used the Shortest Path First (SPF) algorithm.
    // This was an early dynamic routing protocol.
    MIB_IPPROTO_BBN = 12,
    // The Open Shortest Path First (OSPF) protocol,
    // a dynamic routing protocol.
    MIB_IPPROTO_OSPF = 13,
    // The Border Gateway Protocol (BGP), 
    // a dynamic routing protocol.
    MIB_IPPROTO_BGP = 14,
    // A Windows specific entry added originally by 
    // a routing protocol, but which is now static.
    MIB_IPPROTO_NT_AUTOSTATIC = 10002,
    // A Windows specific entry added as a static route from 
    // the routing user interface or a routing command. 
    MIB_IPPROTO_NT_STATIC = 10006,
    // A Windows specific entry added as an static route from
    // the routing user interface or a routing command, 
    // except these routes do not cause Dial On Demand (DOD).
    MIB_IPPROTO_NT_STATIC_NON_DOD = 10007,
}

#[repr(C)]
pub enum NL_ROUTE_ORIGIN {
    // A result of manual configuration. 
    NlroManual = 0i32,
    // A well-known route.
    NlroWellKnown = 1,
    // A result of DHCP configuration.
    NlroDHCP = 2,
    // The result of router advertisement.
    NlroRouterAdvertisement = 3,
    // A result of 6to4 tunneling.
    Nlro6to4 = 4,
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
    pub Protocol: NL_ROUTE_PROTOCOL,   // int/i32 ?
    pub Loopback: BOOLEAN,
    pub AutoconfigureAddress: BOOLEAN,
    pub Publish: BOOLEAN,
    pub Immortal: BOOLEAN,
    pub Age: ULONG,
    pub Origin: NL_ROUTE_ORIGIN,      // int/i32 ?
}

pub type MIB_IPFORWARD_ROW2 = _MIB_IPFORWARD_ROW2;
pub type PMIB_IPFORWARD_ROW2 = *mut MIB_IPFORWARD_ROW2;

#[repr(C)]
pub struct _MIB_IFROW {
    pub wszName: [WCHAR; MAX_INTERFACE_NAME_LEN],
    pub dwIndex: DWORD,
    pub dwType: DWORD,
    pub dwMtu: DWORD,
    pub dwSpeed: DWORD,
    pub dwPhysAddrLen: DWORD,
    pub bPhysAddr: [BYTE; MAXLEN_PHYSADDR],
    pub dwAdminStatus: DWORD,
    pub dwOperStatus: DWORD,
    pub dwLastChange: DWORD,
    pub dwInOctets: DWORD,
    pub dwInUcastPkts: DWORD,
    pub dwInNUcastPkts: DWORD,
    pub dwInDiscards: DWORD,
    pub dwInErrors: DWORD,
    pub dwInUnknownProtos: DWORD,
    pub dwOutOctets: DWORD,
    pub dwOutUcastPkts: DWORD,
    pub dwOutNUcastPkts: DWORD,
    pub dwOutDiscards: DWORD,
    pub dwOutErrors: DWORD,
    pub dwOutQLen: DWORD,
    pub dwDescrLen: DWORD,
    pub bDescr: [BYTE; MAXLEN_IFDESCR],
}

pub type MIB_IFROW = _MIB_IFROW;
pub type PMIB_IFROW = *mut _MIB_IFROW;

#[repr(C)]
pub struct _InterfaceAndOperStatusFlags(pub u8);

impl _InterfaceAndOperStatusFlags {
    pub fn HardwareInterface(&self) -> BOOLEAN {
        self.0 >> 7 
    }

    pub fn FilterInterface(&self) -> BOOLEAN {
        (self.0 >> 6) & 0b_01
    }

    pub fn ConnectorPresent(&self) -> BOOLEAN {
        (self.0 >> 5) & 0b_001
    }

    pub fn NotAuthenticated(&self) -> BOOLEAN {
        (self.0 >> 4) & 0b_0001
    }

    pub fn NotMediaConnected(&self) -> BOOLEAN {
        (self.0 >> 3) & 0b_0000_1
    }

    pub fn Paused(&self) -> BOOLEAN {
        (self.0 >> 2) & 0b_0000_01
    }

    pub fn LowPower(&self) -> BOOLEAN {
        (self.0 >> 1) & 0b_0000_001
    }

    pub fn EndPointInterface(&self) -> BOOLEAN {
        self.0 & 0b_0000_0001
    }
}

#[repr(C)]
pub enum NDIS_MEDIUM {
    // An Ethernet (802.3) network.
    NdisMedium802_3 = 0,
    // A Token Ring (802.5) network.
    NdisMedium802_5 = 1,
    // A Fiber Distributed Data Interface (FDDI) network.
    NdisMediumFddi = 2,
    // A wide area network (WAN). This type covers various forms of point-to-point 
    // and WAN NICs, as well as variant address/header formats that must be negotiated 
    // between the protocol driver and the underlying driver after the binding is established.
    NdisMediumWan = 3,
    // A LocalTalk network.
    NdisMediumLocalTalk = 4,
    // An Ethernet network for which the drivers use the DIX Ethernet header format.
    NdisMediumDix = 5,
    // An ARCNET network.
    NdisMediumArcnetRaw = 6,
    // An ARCNET (878.2) network.
    NdisMediumArcnet878_2 = 7,
    // An ATM network. Connection-oriented client protocol drivers can bind themselves to 
    // an underlying miniport driver that returns this value. Otherwise, legacy protocol 
    // drivers bind themselves to the system-supplied LanE intermediate driver, which 
    // reports its medium type as either NdisMedium802_3 or NdisMedium802_5, depending 
    // on how the LanE driver is configured by the network administrator.
    NdisMediumAtm = 8,
    // A wireless network. NDIS 5.X miniport drivers that support wireless LAN (WLAN) or 
    // wireless WAN (WWAN) packets do not use this NDIS media type, but declare their 
    // media type as NdisMedium802_3 and emulate Ethernet to higher-level NDIS drivers.
    // Note  This media type is supported and can be used for Mobile Broadband only on 
    //       Windows 7, Windows Server 2008 R2, and later.
    NdisMediumWirelessWan = 9,
    // An infrared (IrDA) network.
    NdisMediumIrda = 10,
    // A broadcast PC network.
    NdisMediumBpc = 11,
    // A wide area network in a connection-oriented environment.
    NdisMediumCoWan = 12,
    // An IEEE 1394 (fire wire) network.
    NdisMedium1394 = 13,
    // An InfiniBand network.
    NdisMediumInfiniBand = 14,
    // A tunnel network.
    // Note  This media type is supported on Windows Vista,
    //       Windows Server 2008, and later.
    NdisMediumTunnel = 15,
    // A native IEEE 802.11 network.
    // Note  This media type is supported on Windows Vista,
    //       Windows Server 2008, and later.
    NdisMediumNative802_11 = 16,
    // An NDIS loopback network.
    // Note  This media type is supported on Windows Vista,
    //       Windows Server 2008, and later.
    NdisMediumLoopback = 17,
    // An WiMax network.
    // Note  This media type is supported on Windows 7,
    //       Windows Server 2008 R2, and later.
    NdisMediumWiMax = 18,
}

#[repr(C)]
pub enum NDIS_PHYSICAL_MEDIUM {
    NdisPhysicalMediumUnspecified = 0,
    NdisPhysicalMediumWirelessLan = 1,
    NdisPhysicalMediumCableModem = 2,
    NdisPhysicalMediumPhoneLine = 3,
    NdisPhysicalMediumPowerLine = 4,
    NdisPhysicalMediumDSL = 5,
    NdisPhysicalMediumFibreChannel = 6,
    NdisPhysicalMedium1394 = 7,
    NdisPhysicalMediumWirelessWan = 8,
    NdisPhysicalMediumNative802_11 = 9,
    NdisPhysicalMediumBluetooth = 10,
    NdisPhysicalMediumInfiniband = 11,
    NdisPhysicalMediumWiMax = 12,
    NdisPhysicalMediumUWB = 13,
    NdisPhysicalMedium802_3 = 14,
    NdisPhysicalMedium802_5 = 15,
    NdisPhysicalMediumIrda = 16,
    NdisPhysicalMediumWiredWAN = 17,
    NdisPhysicalMediumWiredCoWan = 18,
    NdisPhysicalMediumOther = 19,
}

#[repr(c)]
pub enum NET_IF_ACCESS_TYPE {
    // Loopback access type. This access type indicates that 
    // the interface loops back transmit data as receive data.
    NET_IF_ACCESS_LOOPBACK = 1, 
    // The LAN access type which includes Ethernet. 
    // This access type indicates that the interface 
    // provides native support for multicast or broadcast services.
    // Note  Mobile broadband interfaces with a MediaType 
    // of NdisMedium802_3 use this access type.
    NET_IF_ACCESS_BROADCAST = 2, 
    // Point-to-point access that supports CoNDIS/WAN, 
    // except for non-broadcast multi-access (NBMA) interfaces.
    // Note  Mobile broadband interfaces with a MediaType 
    // of NdisMediumWirelessWan use this access type.
    NET_IF_ACCESS_POINT_TO_POINT = 3, 
    // Point-to-multipoint access that supports non-broadcast 
    // multi-access (NBMA) media,
    // including the "RAS Internal" interface, and native (non-LANE) ATM.
    NET_IF_ACCESS_POINT_TO_MULTI_POINT = 4, 
    // The maximum possible value for the NET_IF_ACCESS_TYPE enumeration type.
    // This is not a legal value for AccessType member.
    NET_IF_ACCESS_MAXIMUM = 5, 
}

#[repr(c)]
pub enum NET_IF_DIRECTION_TYPE {
    // The send and receive direction type. This direction type 
    // indicates that the NDIS network interface can send and receive data.
    NET_IF_DIRECTION_SENDRECEIVE = 0,
    // The send only direction type. This direction type indicates 
    // that the NDIS network interface can only send data.
    NET_IF_DIRECTION_SENDONLY = 1,
    // The receive only direction type. This direction type indicates 
    // that the NDIS network interface can only receive data.
    NET_IF_DIRECTION_RECEIVEONLY = 2,
    // The maximum possible value for the NET_IF_DIRECTION_TYPE enumeration type.
    // This is not a legal value for DirectionType member.
    NET_IF_DIRECTION_MAXIMUM = 3,
}

#[repr(c)]
pub enum NET_IF_ADMIN_STATUS {
    // The interface is initialized and enabled. But the interface is not 
    // necessarily ready to transmit and receive network data because that 
    // depends on the operational status of the interface.
    NET_IF_ADMIN_STATUS_UP = 1,
    // The interface is down, 
    // and this interface cannot be used to transmit or receive network data.
    NET_IF_ADMIN_STATUS_DOWN = 2,
    // The interface is in a test mode, 
    // and no network data can be transmitted or received.
    NET_IF_ADMIN_STATUS_TESTING = 3,
}

#[repr(c)]
pub enum NET_IF_MEDIA_CONNECT_STATE {
    // The connection state of the interface is unknown.
    MediaConnectStateUnknown = 0,
    // The interface is connected to the network.
    MediaConnectStateConnected = 1,
    // The interface is not connected to the network. 
    MediaConnectStateDisconnected = 2,
}

#[repr(C)]
pub struct _MIB_IF_ROW2 {
    pub InterfaceLuid: NET_LUID,
    pub InterfaceIndex: NET_IFINDEX,
    pub InterfaceGuid: GUID,
    pub Alias: [WCHAR; IF_MAX_STRING_SIZE + 1],
    pub Description: [WCHAR; IF_MAX_STRING_SIZE + 1],
    pub PhysicalAddressLength: ULONG,
    pub PhysicalAddress: [UCHAR; IF_MAX_PHYS_ADDRESS_LENGTH],
    pub PermanentPhysicalAddress: [UCHAR; IF_MAX_PHYS_ADDRESS_LENGTH],
    pub Mtu: ULONG,
    pub Type: IF_TYPE,
    pub TunnelType: TUNNEL_TYPE,
    pub MediaType: NDIS_MEDIUM,
    pub PhysicalMediumType: NDIS_PHYSICAL_MEDIUM,
    pub AccessType: NET_IF_ACCESS_TYPE,
    pub DirectionType: NET_IF_DIRECTION_TYPE,

    pub InterfaceAndOperStatusFlags: _InterfaceAndOperStatusFlags,

    pub OperStatus: IF_OPER_STATUS, 
    pub AdminStatus: NET_IF_ADMIN_STATUS, 
    pub MediaConnectState: NET_IF_MEDIA_CONNECT_STATE, 
    pub NetworkGuid: NET_IF_NETWORK_GUID, 
    pub ConnectionType: NET_IF_CONNECTION_TYPE, 
    pub TransmitLinkSpeed: ULONG64, 
    pub ReceiveLinkSpeed: ULONG64, 
    pub InOctets: ULONG64, 
    pub InUcastPkts: ULONG64, 
    pub InNUcastPkts: ULONG64, 
    pub InDiscards: ULONG64, 
    pub InErrors: ULONG64, 
    pub InUnknownProtos: ULONG64, 
    pub InUcastOctets: ULONG64, 
    pub InMulticastOctets: ULONG64, 
    pub InBroadcastOctets: ULONG64, 
    pub OutOctets: ULONG64, 
    pub OutUcastPkts: ULONG64, 
    pub OutNUcastPkts: ULONG64, 
    pub OutDiscards: ULONG64, 
    pub OutErrors: ULONG64, 
    pub OutUcastOctets: ULONG64, 
    pub OutMulticastOctets: ULONG64, 
    pub OutBroadcastOctets: ULONG64, 
    pub OutQLen: ULONG64, 
}

pub type MIB_IF_ROW2 = _MIB_IF_ROW2;
pub type PMIB_IF_ROW2 = *mut _MIB_IF_ROW2;

#[repr(C)]
pub struct _MIB_IFSTACK_ROW {
    pub HigherLayerInterfaceIndex: NET_IFINDEX,
    pub LowerLayerInterfaceIndex: NET_IFINDEX,
}

pub type MIB_IFSTACK_ROW = _MIB_IFSTACK_ROW;
pub type PMIB_IFSTACK_ROW = *mut _MIB_IFSTACK_ROW;

#[repr(C)]
pub struct _MIB_IFSTACK_TABLE {
    pub NumEntries: ULONG,
    pub Table: [MIB_IFSTACK_ROW; ANY_SIZE],
}

pub type MIB_IFSTACK_TABLE = _MIB_IFSTACK_TABLE;
pub type PMIB_IFSTACK_TABLE = *mut _MIB_IFSTACK_TABLE;

#[repr(C)]
pub struct _MIB_IFTABLE {
    pub dwNumEntries: DWORD,
    pub table: [MIB_IFROW; ANY_SIZE],
}

pub type MIB_IFTABLE = _MIB_IFTABLE;
pub type PMIB_IFTABLE = *mut _MIB_IFTABLE;

#[repr(C)]
pub struct _MIB_IF_TABLE2 {
    pub NumEntries: ULONG,
    pub Table: [MIB_IF_ROW2; ANY_SIZE],
}

pub type MIB_IFTABLE2 = _MIB_IF_TABLE2;
pub type PMIB_IFTABLE2 = *mut _MIB_IF_TABLE2;

#[repr(C)]
pub enum MIB_IF_TABLE_LEVEL {
    MibIfTableNormal,
    MibIfTableRaw,
}

pub type PMIB_IF_TABLE_LEVEL = *mut MIB_IF_TABLE_LEVEL;

#[repr(C)]
pub struct IP_ADAPTER_INDEX_MAP {
    pub Index: ULONG,
    pub Name: [WCHAR; MAX_ADAPTER_NAME],
}

pub type PIP_ADAPTER_INDEX_MAP = *mut IP_ADAPTER_INDEX_MAP;


#[repr(C)]
pub struct _IP_INTERFACE_INFO {
    pub NumAdapters: LONG,
    pub Adapter: [IP_ADAPTER_INDEX_MAP; 1],
}

pub type IP_INTERFACE_INFO = _IP_INTERFACE_INFO;
pub type PIP_INTERFACE_INFO = *mut _IP_INTERFACE_INFO;

#[repr(C)]
pub enum NL_ROUTER_DISCOVERY_BEHAVIOR {
    // Router discovery is disabled.
    RouterDiscoveryDisabled = 0,
    // Router discovery is enabled. This is the default value for IPv6.
    RouterDiscoveryEnabled = 1,
    // Router discovery is configured based on DHCP.
    // This is the default value for IPv4.
    RouterDiscoveryDhcp = 2,
    // This value is used when setting the properties for an IP interface 
    // when the value for router discovery should be unchanged.
    RouterDiscoveryUnchanged = -1,
}

#[repr(C)]
pub enum NL_LINK_LOCAL_ADDRESS_BEHAVIOR {
    // Never use a link local IP address.
    LinkLocalAlwaysOff = 0,
    // Use a link local IP address only if no other address is available.
    // This is the default setting for an IPv4 interface.
    LinkLocalDelayed = 1,
    // Always use a link local IP address.
    // This is the default setting for an IPv6 interface.
    LinkLocalAlwaysOn = 2,
    // This value is used when setting the properties 
    // for an IP interface when the value 
    // for link local address behavior should be unchanged.
    LinkLocalUnchanged = -1,
}

// FIXME: 9 bits
#[repr(C)]
pub struct NL_INTERFACE_OFFLOAD_ROD(pub [u8; 2]);

impl NL_INTERFACE_OFFLOAD_ROD {
    pub fn NlChecksumSupported(&self) -> BOOLEAN {
        self.0[0] >> 7
    }
    pub fn NlOptionsSupported(&self) -> BOOLEAN {
        (self.0[0] >> 6) & 0b_01
    }
    pub fn TlDatagramChecksumSupported(&self) -> BOOLEAN {
        (self.0[0] >> 5) & 0b_001
    }
    pub fn TlStreamChecksumSupported(&self) -> BOOLEAN {
        (self.0[0] >> 4) & 0b_0001
    }
    pub fn TlStreamOptionsSupported(&self) -> BOOLEAN {
        (self.0[0] >> 3) & 0b_0000_1
    }
    pub fn TlStreamFastPathCompatible(&self) -> BOOLEAN {
        (self.0[0] >> 2) & 0b_0000_01
    }
    pub fn TlDatagramFastPathCompatible(&self) -> BOOLEAN {
        (self.0[0] >> 1) & 0b_0000_001
    }
    pub fn TlLargeSendOffloadSupported(&self) -> BOOLEAN {
        self.0[0] & 0b_0000_0001
    }
    pub fn TlGiantSendOffloadSupported(&self) -> BOOLEAN {
        self.0[1] >> 7
    }
}

#[repr(C)]
pub struct _MIB_IPINTERFACE_ROW {
    pub Family: ADDRESS_FAMILY,
    pub InterfaceLuid: NET_LUID,
    pub InterfaceIndex: NET_IFINDEX,
    pub MaxReassemblySize: ULONG,
    pub InterfaceIdentifier: ULONG64,
    pub MinRouterAdvertisementInterval: ULONG,
    pub MaxRouterAdvertisementInterval: ULONG,
    pub AdvertisingEnabled: BOOLEAN,
    pub ForwardingEnabled: BOOLEAN,
    pub WeakHostSend: BOOLEAN,
    pub WeakHostReceive: BOOLEAN,
    pub UseAutomaticMetric: BOOLEAN,
    pub UseNeighborUnreachabilityDetection: BOOLEAN,
    pub ManagedAddressConfigurationSupported: BOOLEAN,
    pub OtherStatefulConfigurationSupported: BOOLEAN,
    pub AdvertiseDefaultRoute: BOOLEAN,
    pub RouterDiscoveryBehavior: NL_ROUTER_DISCOVERY_BEHAVIOR,
    pub DadTransmits: ULONG,
    pub BaseReachableTime: ULONG,
    pub RetransmitTime: ULONG,
    pub PathMtuDiscoveryTimeout: ULONG,
    pub LinkLocalAddressBehavior: NL_LINK_LOCAL_ADDRESS_BEHAVIOR,
    pub LinkLocalAddressTimeout: ULONG,
    pub ZoneIndices: [ULONG; ScopeLevelCount],
    pub SitePrefixLength: ULONG,
    pub Metric: ULONG,
    pub NlMtu: ULONG,
    pub Connected: BOOLEAN,
    pub SupportsWakeUpPatterns: BOOLEAN,
    pub SupportsNeighborDiscovery: BOOLEAN,
    pub SupportsRouterDiscovery: BOOLEAN,
    pub ReachableTime: ULONG,
    // C bitfields
    pub TransmitOffload: NL_INTERFACE_OFFLOAD_ROD,
    pub ReceiveOffload: NL_INTERFACE_OFFLOAD_ROD,
    pub DisableDefaultRoutes: NL_INTERFACE_OFFLOAD_ROD,

    pub DisableDefaultRoutes: BOOLEAN,
}

pub type MIB_IPINTERFACE_ROW = _MIB_IPINTERFACE_ROW;
pub type PMIB_IPINTERFACE_ROW = *mut _MIB_IPINTERFACE_ROW;

#[repr(C)]
pub struct _MIB_IPINTERFACE_TABLE {
    pub NumEntries: ULONG,
    pub Table: [MIB_IPINTERFACE_ROW; ANY_SIZE],
}

pub type MIB_IPINTERFACE_TABLE = _MIB_IPINTERFACE_TABLE;
pub type PMIB_IPINTERFACE_TABLE = *mut _MIB_IPINTERFACE_TABLE;

#[repr(C)]
pub struct MIB_IPADDRROW {
    pub dwAddr: DWORD,
    pub dwIndex: DWORD,
    pub dwMask: DWORD,
    pub dwBCastAddr: DWORD,
    pub dwReasmSize: DWORD,
    pub unused1: c_ushort,
    pub wType: c_ushort
}

pub type PMIB_IPADDRROW = *mut MIB_IPADDRROW;


#[repr(C)]
pub struct _MIB_IPADDRTABLE {
    pub dwNumEntries: DWORD,
    pub table: [MIB_IPADDRROW; ANY_SIZE],
}

pub type MIB_IPADDRTABLE = _MIB_IPADDRTABLE;
pub type PMIB_IPADDRTABLE = *mut _MIB_IPADDRTABLE;

#[repr(C)]
pub struct _MIB_IPFORWARDTABLE {
    pub dwNumEntries: DWORD,
    pub table: [MIB_IPFORWARDROW; ANY_SIZE],
}

pub type MIB_IPFORWARDTABLE = _MIB_IPFORWARDTABLE;
pub type PMIB_IPFORWARDTABLE = *mut _MIB_IPFORWARDTABLE;

#[repr(C)]
pub struct _MIB_IPFORWARD_TABLE2 {
    pub NumEntries: ULONG,
    pub Table: [MIB_IPFORWARD_ROW2; ANY_SIZE],
}

pub type MIB_IPFORWARD_TABLE2 = _MIB_IPFORWARD_TABLE2;
pub type PMIB_IPFORWARD_TABLE2 = *mut _MIB_IPFORWARD_TABLE2;

#[repr(C)]
pub struct _MIB_IPSTATS {
    pub dwForwarding: DWORD,
    pub dwDefaultTTL: DWORD,
    pub dwInReceives: DWORD,
    pub dwInHdrErrors: DWORD,
    pub dwInAddrErrors: DWORD,
    pub dwForwDatagrams: DWORD,
    pub dwInUnknownProtos: DWORD,
    pub dwInDiscards: DWORD,
    pub dwInDelivers: DWORD,
    pub dwOutRequests: DWORD,
    pub dwRoutingDiscards: DWORD,
    pub dwOutDiscards: DWORD,
    pub dwOutNoRoutes: DWORD,
    pub dwReasmTimeout: DWORD,
    pub dwReasmReqds: DWORD,
    pub dwReasmOks: DWORD,
    pub dwReasmFails: DWORD,
    pub dwFragOks: DWORD,
    pub dwFragFails: DWORD,
    pub dwFragCreates: DWORD,
    pub dwNumIf: DWORD,
    pub dwNumAddr: DWORD,
    pub dwNumRoutes: DWORD,
}

pub type MIB_IPSTATS = _MIB_IPSTATS;
pub type PMIB_IPSTATS = *mut _MIB_IPSTATS;




// NO_ERROR or ERROR_INVALID_PARAMETER / ERROR_FILE_NOT_FOUND / ERROR_NOT_SUPPORTED / Other
pub type NETIOAPI_API = DWORD;



#[link(name = "iphlpapi")]
extern "system" {
    // Adapter Management
    pub fn GetAdapterIndex(AdapterName: LPWSTR, IfIndex: PULONG) -> DWORD;
    pub fn GetAdaptersAddresses(Family: ULONG,
                                Flags: ULONG,
                                Reserved: PVOID,
                                AdapterAddresses: PIP_ADAPTER_ADDRESSES,
                                SizePointer: PULONG) -> ULONG;
    /// The GetAdaptersInfo function retrieves adapter information for the local computer.
    /// On Windows XP and later:  Use the GetAdaptersAddresses function instead of GetAdaptersInfo.
    pub fn GetAdaptersInfo(pAdapterInfo: PIP_ADAPTER_INFO, pOutBufLen: PULONG) -> DWORD;
    pub fn GetPerAdapterInfo(IfIndex: ULONG,
                             pPerAdapterInfo: PIP_PER_ADAPTER_INFO,
                             pOutBufLen: PULONG) -> DWORD;
    pub fn GetUniDirectionalAdapterInfo(pIPIfInfo: PIP_UNIDIRECTIONAL_ADAPTER_ADDRESS,
                                        dwOutBufLen: PULONG) -> DWORD;

    // Address Resolution Protocol (ARP) Management
    //    
    // CreateIpNetEntry
    // CreateProxyArpEntry
    // DeleteIpNetEntry
    // DeleteProxyArpEntry
    // FlushIpNetTable
    // GetIpNetTable
    // SendARP
    // SetIpNetEntry

    // Interface Conversion
    //    
    // ConvertInterfaceAliasToLuid
    // ConvertInterfaceGuidToLuid
    // ConvertInterfaceIndexToLuid
    // ConvertInterfaceLuidToAlias
    // ConvertInterfaceLuidToGuid
    // ConvertInterfaceLuidToIndex
    // ConvertInterfaceLuidToNameA
    // ConvertInterfaceLuidToNameW
    // ConvertInterfaceNameToLuidA
    // ConvertInterfaceNameToLuidW
    pub fn if_indextoname(InterfaceIndex: NET_IFINDEX, InterfaceName: PCHAR) -> PCHAR;
    pub fn if_nametoindex(InterfaceName: PCSTR) -> NET_IFINDEX;

    // Interface Management
    pub fn GetFriendlyIfIndex(IfIndex: DWORD) -> DWORD;
    pub fn GetIfEntry(pIfRow: PMIB_IFROW) -> DWORD;
    pub fn GetIfEntry2(Row: PMIB_IF_ROW2) -> NETIOAPI_API;
    pub fn GetIfEntry2Ex(Level: MIB_IF_ENTRY_LEVEL, Row: PMIB_IF_ROW2) -> NETIOAPI_API;
    pub fn GetIfStackTable(Table: PMIB_IFSTACK_TABLE) -> NETIOAPI_API;
    pub fn GetIfTable(pIfTable: PMIB_IFTABLE, pdwSize: PULONG, bOrder: BOOL) -> DWORD;
    pub fn GetIfTable2(Table: PMIB_IF_TABLE2) -> NETIOAPI_API;
    pub fn GetIfTable2Ex(Level: MIB_IF_TABLE_LEVEL, Table: PMIB_IF_TABLE2) -> NETIOAPI_API;
    pub fn GetInterfaceInfo(pIfTable: PIP_INTERFACE_INFO, dwOutBufLen: PULONG) -> DWORD;
    // GetInvertedIfStackTable
    pub fn GetIpInterfaceEntry(Row: PMIB_IPINTERFACE_ROW) -> NETIOAPI_API;
    pub fn GetIpInterfaceTable(Family: ADDRESS_FAMILY, Table: PMIB_IPINTERFACE_TABLE) -> NETIOAPI_API;
    pub fn GetNumberOfInterfaces(pdwNumIf: PDWORD) -> DWORD;
    pub fn InitializeIpInterfaceEntry(Row: PMIB_IPINTERFACE_ROW) -> VOID;
    pub fn SetIfEntry(pIfRow: PMIB_IFROW) -> DWORD;
    pub fn SetIpInterfaceEntry(Row: PMIB_IPINTERFACE_ROW) -> NETIOAPI_API;
    
    // Internet Protocol (IP) and Internet Control Message Protocol (ICMP)
    // GetIcmpStatistics
    // GetIpStatistics
    // Icmp6CreateFile
    // Icmp6ParseReplies
    // Icmp6SendEcho2
    // IcmpCloseHandle
    // IcmpCreateFile
    // IcmpParseReplies
    // IcmpSendEcho
    // IcmpSendEcho2
    // IcmpSendEcho2Ex
    // SetIpTTL

    // IP Address Management
    pub fn AddIPAddress(Address: IPAddr,
                        IpMask: IPMask,
                        IfIndex: DWORD,
                        NTEContext: PULONG,
                        NTEInstance: PULONG) -> DWORD;
    // CreateAnycastIpAddressEntry
    // CreateUnicastIpAddressEntry
    pub fn DeleteIPAddress(NTEContext: ULONG) -> DWORD;
    // DeleteAnycastIpAddressEntry
    // DeleteUnicastIpAddressEntry
    // GetAnycastIpAddressEntry
    // GetAnycastIpAddressTable
    pub fn GetIpAddrTable(pIpAddrTable: PMIB_IPADDRTABLE, pdwSize: PULONG, bOrder: BOOL) -> DWORD;
    // GetMulticastIpAddressEntry
    // GetMulticastIpAddressTable
    // GetUnicastIpAddressEntry
    // GetUnicastIpAddressTable
    // InitializeUnicastIpAddressEntry
    pub fn IpReleaseAddress(AdapterInfo: PIP_ADAPTER_INDEX_MAP) -> DWORD;
    pub fn IpRenewAddress(AdapterInfo: PIP_ADAPTER_INDEX_MAP) -> DWORD;
    // NotifyStableUnicastIpAddressTable
    // SetUnicastIpAddressEntry

    // IP Address String Conversion
    //
    // RtlIpv4AddressToString
    // RtlIpv4AddressToStringEx
    // RtlIpv4StringToAddress
    // RtlIpv4StringToAddressEx
    // RtlIpv6AddressToString
    // RtlIpv6AddressToStringEx
    // RtlIpv6StringToAddress
    // RtlIpv6StringToAddressEx

    // IP Neighbor Address Management
    //
    // CreateIpNetEntry2
    // DeleteIpNetEntry2
    // FlushIpNetTable2
    // GetIpNetEntry2
    // GetIpNetTable2
    // ResolveIpNetEntry2
    // ResolveNeighbor
    // SetIpNetEntry2

    // IP Path Management
    //
    // FlushIpPathTable
    // GetIpPathEntry
    // GetIpPathTable

    // IP Route Management
    pub fn CreateIpForwardEntry(pRoute: PMIB_IPFORWARDROW) -> DWORD;
    //  (_In_ const MIB_IPFORWARD_ROW2 *Row)
    pub fn CreateIpForwardEntry2(Row: *mut *const MIB_IPFORWARD_ROW2) -> DWORD;
    pub fn DeleteIpForwardEntry(pRoute: PMIB_IPFORWARDROW) -> DWORD;
    pub fn DeleteIpForwardEntry2(Row: *mut *const MIB_IPFORWARD_ROW2) -> NETIOAPI_API;
    pub fn EnableRouter(pHandle: *mut HANDLE, pOverlapped: *mut OVERLAPPED) -> DWORD;
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
    pub fn GetIpForwardEntry2(Row: PMIB_IPFORWARD_ROW2) -> NETIOAPI_API;
    pub fn GetIpForwardTable(pIpForwardTable: PMIB_IPFORWARDTABLE, pdwSize: PULONG, bOrder: BOOL) -> DWORD;
    pub fn GetIpForwardTable2(Family: ADDRESS_FAMILY, Table: PMIB_IPFORWARD_TABLE2) -> NETIOAPI_API;
    pub fn GetRTTAndHopCount(DestIpAddress: IPAddr, HopCount: PULONG, MaxHops: ULONG, RTT: PULONG) -> BOOL;
    pub fn InitializeIpForwardEntry(Row: PMIB_IPFORWARD_ROW2) -> VOID;
    pub fn SetIpForwardEntry(pRoute: PMIB_IPFORWARDROW) -> DWORD;
    pub fn SetIpForwardEntry2(Route: *mut *const MIB_IPFORWARD_ROW2) -> NETIOAPI_API;
    pub fn SetIpStatistics(pIpStats: PMIB_IPSTATS) -> DWORD;
    pub fn SetIpStatisticsEx(pIpStats: PMIB_IPSTATS, Family: ULONG) -> DWORD;
    pub fn UnenableRouter(pOverlapped: *mut OVERLAPPED, lpdwEnableCount: LPDWORD) -> DWORD;
    
    // IP Table Memory Management
    pub fn FreeMibTable(Memory: PVOID) -> VOID;
    
    // IP Utility
    // 
    // ConvertIpv4MaskToLength
    // ConvertLengthToIpv4Mask
    // CreateSortedAddressPairs
    // ParseNetworkString

    // Network Configuration
    // 
    // GetNetworkParams

    // Notification
    // 
    // CancelMibChangeNotify2
    // NotifyAddrChange
    // NotifyIpInterfaceChange
    // NotifyRouteChange
    // NotifyRouteChange2
    // NotifyUnicastIpAddressChange

    // Persistent Port Reservarion
    // 
    // CreatePersistentTcpPortReservation
    // CreatePersistentUdpPortReservation
    // DeletePersistentTcpPortReservation
    // DeletePersistentUdpPortReservation
    // LookupPersistentTcpPortReservation
    // LookupPersistentUdpPortReservation

    // Security Health
    // 
    // CancelSecurityHealthChangeNotify
    // NotifySecurityHealthChange

    // Teredo IPv6 Client Management
    // 
    // GetTeredoPort
    // NotifyTeredoPortChange
    // NotifyStableUnicastIpAddressTable

    // Transmission Control Protocol (TCP) and User Datagram Protocol (UDP)
    // 
    // GetExtendedTcpTable
    // GetExtendedUdpTable
    // GetOwnerModuleFromTcp6Entry
    // GetOwnerModuleFromTcpEntry
    // GetOwnerModuleFromUdp6Entry
    // GetOwnerModuleFromUdpEntry
    // GetPerTcp6ConnectionEStats
    // GetPerTcpConnectionEStats
    // GetTcpStatistics
    // GetTcpStatisticsEx
    // GetTcpStatisticsEx2
    // GetTcp6Table
    // GetTcp6Table2
    // GetTcpTable
    // GetTcpTable2
    // SetPerTcp6ConnectionEStats
    // SetPerTcpConnectionEStats
    // SetTcpEntry
    // GetUdp6Table
    // GetUdpStatistics
    // GetUdpStatisticsEx
    // GetUdpStatisticsEx2
    // GetUdpTable

    // Deprecated APIs
    // 
    // AllocateAndGetTcpExTableFromStack
    // AllocateAndGetUdpExTableFromStack

}