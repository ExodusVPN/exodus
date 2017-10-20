
registries = ['afrinic', 'apnic', 'arin', 'iana', 'ietf', 'lacnic', 'ripencc']
descp = [
    "Africa Region", "Asia/Pacific Region", 
    "Canada, USA, and some Caribbean Islands",
    "Internet Assigned Numbers Authority(IANA)", "Internet Engineering Task Force(IETF), Special Registry",
    "Latin America and some Caribbean Islands", "Europe, the Middle East, and Central Asia"
]


rust_code = """
/// Number Resources: https://www.iana.org/numbers
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Registry {
"""
for x in registries:
    rust_code += "    /// %s\n" % ( descp[registries.index(x)] )
    rust_code += "    %s,\n" % (x[0].upper()+x[1:])
rust_code += "}\n"


rust_code += """
impl Registry {
    pub fn new(n: u8) -> Result<Self, &'static str> {
        match n {
"""
for i in range(len(registries)):
    name_l = registries[i]
    name_u = name_l[0].upper()+name_l[1:]
    rust_code += "            %d => Ok(Registry::%s), \n" % (i, name_u)
rust_code += "            _ => Err(\"Oh, no ...\")\n"
rust_code += "        }\n"
rust_code += "    }\n"

rust_code += """
    pub fn from_u8(n: u8) -> Result<Self, &'static str> {
        Registry::new(n)
    }
"""

rust_code += """
    pub fn to_u8(&self) -> u8 {
        match *self {
"""
for i in range(len(registries)):
    name_l = registries[i]
    name_u = name_l[0].upper()+name_l[1:]
    rust_code += "            Registry::%s => %d, \n" % (name_u, i)
rust_code += "        }\n"
rust_code += "    }\n"


rust_code += """
    pub fn from_str(s: &str) -> Result<Self, &'static str> {
        match s {
"""
for i in range(len(registries)):
    name_l = registries[i]
    name_u = name_l[0].upper()+name_l[1:]
    rust_code += "            \"%s\" => Ok(Registry::%s), \n" % (name_l, name_u)
rust_code += "            _ => Err(\"Oh, no ...\")\n"
rust_code += "        }\n"
rust_code += "    }\n"


rust_code += """
    pub fn to_str(&self) -> &str {
        match *self {
"""
for i in range(len(registries)):
    name_l = registries[i]
    name_u = name_l[0].upper()+name_l[1:]
    rust_code += "            Registry::%s => \"%s\", \n" % (name_u, name_l)
rust_code += "        }\n"
rust_code += "    }\n"


rust_code += """
    pub fn description(&self) -> &str {
        match *self {
"""
for i in range(len(registries)):
    name_l = registries[i]
    name_u = name_l[0].upper()+name_l[1:]
    rust_code += "            Registry::%s => \"%s\", \n" % (name_u, descp[registries.index(name_l)])
rust_code += "        }\n"
rust_code += "    }\n"


rust_code += "}\n"

print(rust_code)

