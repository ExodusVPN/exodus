
# 1,0,22,150,       - Unassigned (Released 18 October 2005),

s = """0,0,0,0,EOOL   - End of Options List,[RFC791][Jon_Postel]
0,0,1,1,NOP    - No Operation,[RFC791][Jon_Postel]
1,0,2,130,SEC    - Security,[RFC1108]
1,0,3,131,LSR    - Loose Source Route,[RFC791][Jon_Postel]
0,2,4,68,TS     - Time Stamp,[RFC791][Jon_Postel]
1,0,5,133,E-SEC  - Extended Security,[RFC1108]
1,0,6,134,CIPSO  - Commercial Security,[draft-ietf-cipso-ipsecurity-01]
0,0,7,7,RR     - Record Route,[RFC791][Jon_Postel]
1,0,8,136,SID    - Stream ID,[RFC791][Jon_Postel][RFC6814][1]
1,0,9,137,SSR    - Strict Source Route,[RFC791][Jon_Postel]
0,0,10,10,ZSU    - Experimental Measurement,[ZSu]
0,0,11,11,MTUP   - MTU Probe,[RFC1063][RFC1191][1]
0,0,12,12,MTUR   - MTU Reply,[RFC1063][RFC1191][1]
1,2,13,205,FINN   - Experimental Flow Control,[Greg_Finn]
1,0,14,142,VISA   - Experimental Access Control,[Deborah_Estrin][RFC6814][1]
0,0,15,15,ENCODE - ???,[VerSteeg][RFC6814][1]
1,0,16,144,IMITD  - IMI Traffic Descriptor,[Lee]
1,0,17,145,EIP    - Extended Internet Protocol,[RFC1385][RFC6814][1]
0,2,18,82,TR     - Traceroute,[RFC1393][RFC6814][1]
1,0,19,147,ADDEXT - Address Extension,[Ullmann IPv7][RFC6814][1]
1,0,20,148,RTRALT - Router Alert,[RFC2113]
1,0,21,149,SDB    - Selective Directed Broadcast,[Charles_Bud_Graff][RFC6814][1]
1,0,23,151,DPS    - Dynamic Packet State,[Andy_Malis][RFC6814][1]
1,0,24,152,UMP    - Upstream Multicast Pkt.,[Dino_Farinacci][RFC6814][1]
0,0,25,25,QS     - Quick-Start,[RFC4782]
0,0,30,30,EXP1    - RFC3692-style Experiment [2],[RFC4727]
0,2,30,94,EXP2    - RFC3692-style Experiment [2],[RFC4727]
1,0,30,158,EXP3    - RFC3692-style Experiment [2],[RFC4727]
1,2,30,222,EXP4    - RFC3692-style Experiment [2],[RFC4727]"""

data = {}
code = ""
for line in s.split("\n"):
    copy, kind, number, value, name_descp, refs = line.split(",")
    name = name_descp.split(" - ")[0].strip().replace("-", "_")
    descp = name_descp.split(" - ")[1].strip()
    copy = int(copy)
    kind = int(kind)
    number = int(number)
    value = int(value)
    data[name] = {
        'copy': copy,
        'kind': kind,
        'number': number,
        'value': value,
        'name': name,
        'descp': descp,
        'refs': refs,
        'class': int(bin(copy).replace("0b", "").zfill(1) + bin(kind).replace("0b", "").zfill(2) + bin(number).replace("0b", "").zfill(5), 2)
    }

code += """
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq)]
pub enum Ipv4OptionClass {
"""
for k in data.keys():
    code += "    {}, // {}, {}\n".format(k, data[k]['descp'], data[k]['refs'])
code += "}\n"
code += """
impl Ipv4OptionClass {
"""

code_fn1 = """    pub fn new(ccn: u8, value: u8) -> Result<Self, ::std::io::Error> {
        match (ccn, value) {
"""
for k in data.keys():
    v = data[k]
    code_fn1 += "            (%d, %d) => Ok(Ipv4OptionClass::%s),\n" % (v['class'], v['value'], v['name'], )
code_fn1 += '            (_, _) => Err(::std::io::Error::new(::std::io::ErrorKind::Other, \"IPv4 Options value error (copy/class/number/value) ...\"))\n'
code_fn1 += "        }\n"
code_fn1 += "    }\n"

code_fn2 = """
    /// Option copy field
    pub fn copied(&self) -> u8 {
        match *self {
"""
for k in data.keys():
    v = data[k]
    code_fn2 += "            Ipv4OptionClass::%s => %d,\n" % (v['name'], v['copy'])
code_fn2 += "        }\n"
code_fn2 += "    }\n"


code_fn3 = """
    /// Option class field
    pub fn kind(&self) -> u8 {
        match *self {
"""
for k in data.keys():
    v = data[k]
    code_fn3 += "            Ipv4OptionClass::%s => %d,\n" % (v['name'], v['kind'])
code_fn3 += "        }\n"
code_fn3 += "    }\n"

code_fn4 = """
    /// Option number field
    pub fn number(&self) -> u8 {
        match *self {
"""
for k in data.keys():
    v = data[k]
    code_fn4 += "            Ipv4OptionClass::%s => %d,\n" % (v['name'], v['number'])
code_fn4 += "        }\n"
code_fn4 += "    }\n"

code_fn5 = """
    /// Option (copy, class, number) fields
    pub fn ccn(&self) -> u8 {
        match *self {
"""
for k in data.keys():
    v = data[k]
    code_fn5 += "            Ipv4OptionClass::%s => %d, // %s\n" % (v['name'], v['class'], bin(v['class']))
code_fn5 += "        }\n"
code_fn5 += "    }\n"

code_fn6 = """
    /// Option value(length) field
    pub fn length(&self) -> u8 {
        match *self {
"""
for k in data.keys():
    v = data[k]
    code_fn6 += "            Ipv4OptionClass::%s => %d,\n" % (v['name'], v['value'])
code_fn6 += "        }\n"
code_fn6 += "    }\n"

code_fn7 = """    pub fn description(&self) -> &'static str {
        match *self {
"""
for k in data.keys():
    v = data[k]
    code_fn7 += "            Ipv4OptionClass::%s => \"%s , %s\",\n" % (v['name'], v['descp'], v['refs'])
code_fn7 += "        }\n"
code_fn7 += "    }\n"

code += code_fn1
code += code_fn2
code += code_fn3
code += code_fn4
code += code_fn5
code += code_fn6
code += code_fn7
code += "}\n"

print("""

/// IPv4 OPTION NUMBERS
/// 
/// https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ip-parameters-1
///
/// Format:
/// 
///     copy  : 1  bits
///     class : 2  bits
///     number: 5  bits
///     value : 8  bits
///     data  : .. bits
#[derive(Debug, PartialEq, Eq)]
pub struct Ipv4Option<'a> {
    /// Option Fields: copied(copy), class, number, value(length)
    kind: Ipv4OptionClass,
    /// Option-specific data. This field may not exist for simple options.
    data: &'a [u8]
}

impl <'a>Ipv4Option<'a> {
    pub fn new(kind: Ipv4OptionClass, data: &'a [u8]) -> Result<Self, ::std::io::Error>{
        Ok(Ipv4Option {
            kind: kind,
            data: data
        })
    }
    pub fn kind(&self) -> &Ipv4OptionClass {
        &self.kind
    }
    pub fn data(&self) -> &'a [u8] {
        &self.data
    }
}


""")

    


# service_list = ["NetworkControl", "CRITIC_ECP", "FlashOverride", "Flash", "Immediate", "Priority", "Routine"]

# opts = [
#     ["Delay::Normal", "Delay::Low"],
#     ["Throughput::Normal", "Throughput::High"],
#     ["Relibility::Normal", "Relibility::High"]
# ]

# code2 = """
# pub enum ServiceKind {
#     NetworkControl(Delay, Throughput, Relibility),
#     InternetworkControl(Delay, Throughput, Relibility),
#     CRITIC_ECP(Delay, Throughput, Relibility),
#     FlashOverride(Delay, Throughput, Relibility),
#     Flash(Delay, Throughput, Relibility),
#     Immediate(Delay, Throughput, Relibility),
#     Priority(Delay, Throughput, Relibility),
#     Routine(Delay, Throughput, Relibility)
# }

# impl ServiceKind {
#     pub fn to_u8(&self) -> u8 {
#         match *self {
# """
# """
#     pub fn new(n: u8) -> Result<Self, ::std::io::Error> {
        
#     }
# """
#           111 - Network Control
#           110 - Internetwork Control
#           101 - CRITIC/ECP
#           100 - Flash Override
#           011 - Flash
#           010 - Immediate
#           001 - Priority
#           000 - Routine

# for x in service_list:
#     for opt in opts:
#         for y in opt:
#             code2 += "            ServiceKind::%s() => "

print(code)
