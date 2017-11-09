


/// IANA IPv4 Special-Purpose Address Registry
///
/// https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
///
/// Address Block   Name    RFC     Allocation Date     Termination Date
/// Source  Destination     Forwardable     Globally Reachable
/// Reserved-by-Protocol
/// 0.0.0.0/8   "This host on this network"     [RFC1122], Section 3.2.1.3
/// 1981-09     N/A     True    False   False   False   True
/// 10.0.0.0/8  Private-Use     [RFC1918]   1996-02     N/A     True
/// True    True    False   False
/// 100.64.0.0/10   Shared Address Space    [RFC6598]   2012-04     N/A
/// True    True    True    False   False
/// 127.0.0.0/8     Loopback    [RFC1122], Section 3.2.1.3  1981-09     N/A
/// False [1]   False [1]   False [1]   False [1]   True
/// 169.254.0.0/16  Link Local  [RFC3927]   2005-05     N/A     True
/// True    False   False   True
/// 172.16.0.0/12   Private-Use     [RFC1918]   1996-02     N/A     True
/// True    True    False   False
/// 192.0.0.0/24 [2]    IETF Protocol Assignments   [RFC6890], Section 2.1
/// 2010-01     N/A     False   False   False   False   False
/// 192.0.0.0/29    IPv4 Service Continuity Prefix  [RFC7335]   2011-06
/// N/A     True    True    True    False   False
/// 192.0.0.8/32    IPv4 dummy address  [RFC7600]   2015-03     N/A
/// True    False   False   False   False
/// 192.0.0.9/32    Port Control Protocol Anycast   [RFC7723]   2015-10
/// N/A     True    True    True    True    False
/// 192.0.0.10/32   Traversal Using Relays around NAT Anycast   [RFC8155]
/// 2017-02     N/A     True    True    True    True    False
/// 192.0.0.170/32, 192.0.0.171/32  NAT64/DNS64 Discovery   [RFC7050],
/// Section 2.2  2013-02     N/A     False   False   False   False   True
/// 192.0.2.0/24    Documentation (TEST-NET-1)  [RFC5737]   2010-01     N/A
/// False   False   False   False   False
/// 192.31.196.0/24     AS112-v4    [RFC7535]   2014-12     N/A     True
/// True    True    True    False
/// 192.52.193.0/24     AMT     [RFC7450]   2014-12     N/A     True
/// True    True    True    False
/// 192.88.99.0/24  Deprecated (6to4 Relay Anycast)     [RFC7526]   2001-06
/// 2015-03
/// 192.168.0.0/16  Private-Use     [RFC1918]   1996-02     N/A     True
/// True    True    False   False
/// 192.175.48.0/24     Direct Delegation AS112 Service     [RFC7534]
/// 1996-01     N/A     True    True    True    True    False
/// 198.18.0.0/15   Benchmarking    [RFC2544]   1999-03     N/A     True
/// True    True    False   False
/// 198.51.100.0/24     Documentation (TEST-NET-2)  [RFC5737]   2010-01
/// N/A     False   False   False   False   False
/// 203.0.113.0/24  Documentation (TEST-NET-3)  [RFC5737]   2010-01     N/A
/// False   False   False   False   False
/// 240.0.0.0/4     Reserved    [RFC1112], Section 4    1989-08     N/A
/// False   False   False   False   True
/// 255.255.255.255/32  Limited Broadcast   [RFC8190] [RFC919], Section 7
/// 1984-10     N/A     False   True    False   False   True

/// IANA IPv6 Special-Purpose Address Registry
///
/// https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
///
/// Address Block    Name    RFC     Allocation Date     Termination Date
/// Source  Destination     Forwardable     Globally Reachable
/// Reserved-by-Protocol
/// ::1/128     Loopback Address    [RFC4291]   2006-02     N/A     False
/// False   False   False   True
/// ::/128  Unspecified Address     [RFC4291]   2006-02     N/A     True
/// False   False   False   True
/// ::ffff:0:0/96   IPv4-mapped Address     [RFC4291]   2006-02     N/A
/// False   False   False   False   True
/// 64:ff9b::/96    IPv4-IPv6 Translat.     [RFC6052]   2010-10     N/A
/// True    True    True    True    False
/// 64:ff9b:1::/48  IPv4-IPv6 Translat.     [RFC8215]   2017-06     N/A
/// True    True    True    False   False
/// 100::/64    Discard-Only Address Block  [RFC6666]   2012-06     N/A
/// True    True    True    False   False
/// 2001::/23   IETF Protocol Assignments   [RFC2928]   2000-09     N/A
/// False [1]   False [1]   False [1]   False [1]   False
/// 2001::/32   TEREDO  [RFC4380] [RFC8190]     2006-01     N/A     True
/// True    True    N/A [2]     False
/// 2001:1::1/128   Port Control Protocol Anycast   [RFC7723]   2015-10
/// N/A     True    True    True    True    False
/// 2001:1::2/128   Traversal Using Relays around NAT Anycast   [RFC8155]
/// 2017-02     N/A     True    True    True    True    False
/// 2001:2::/48     Benchmarking    [RFC5180][RFC Errata 1752]  2008-04
/// N/A     True    True    True    False   False
/// 2001:3::/32     AMT     [RFC7450]   2014-12     N/A     True    True
/// True    True    False
/// 2001:4:112::/48     AS112-v6    [RFC7535]   2014-12     N/A     True
/// True    True    True    False
/// 2001:5::/32     EID Space for LISP (Managed by RIPE NCC)    [RFC7954]
/// 2016-09     2019-09 [3]     True [4]    True    True    True    True [5]
/// 2001:10::/28    Deprecated (previously ORCHID)  [RFC4843]   2007-03
/// 2014-03
/// 2001:20::/28    ORCHIDv2    [RFC7343]   2014-07     N/A     True
/// True    True    True    False
/// 2001:db8::/32   Documentation   [RFC3849]   2004-07     N/A     False
/// False   False   False   False
/// 2002::/16 [6]   6to4    [RFC3056]   2001-02     N/A     True    True
/// True    N/A [6]     False
/// 2620:4f:8000::/48   Direct Delegation AS112 Service     [RFC7534]
/// 2011-05     N/A     True    True    True    True    False
/// fc00::/7    Unique-Local    [RFC4193] [RFC8190]     2005-10     N/A
/// True    True    True    False [7]   False
/// fe80::/10   Link-Local Unicast  [RFC4291]   2006-02     N/A     True
/// True    False   False   True

pub fn is_private_use() {
    unimplemented!()
}
