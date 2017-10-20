
# IP Number Status codegen
# pub static IP_NUMBER_STATUS_SET: [&'static str; 11] = ["afrinic", "allocated", "apnic", "arin", "assigned", "available", "iana", "ietf", "lacnic", "reserved", "ripencc"];

status_set = ["afrinic", "allocated", "apnic", "arin", "assigned", "available", "iana", "ietf", "lacnic", "reserved", "ripencc"]
registry_list = ["afrinic", "apnic", "arin", "iana", "ietf", "lacnic", "ripencc"]

rust_code = """

// pub static IP_NUMBER_STATUS_SET: [&'static str; 11] = ["afrinic", "allocated", "apnic", "arin", "assigned", "available", "iana", "ietf", "lacnic", "reserved", "ripencc"];


#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Status {
"""
for x in status_set:
    rust_code += "    %s,\n" % (x[0].upper()+x[1:])
rust_code += "}\n"


rust_code += """
impl Status {
    pub fn new(n: u8) -> Result<Self, &'static str> {
        match n {
"""
for i in range(len(status_set)):
    name_l = status_set[i]
    name_u = name_l[0].upper()+name_l[1:]
    rust_code += "            %d => Ok(Status::%s), \n" % (i, name_u)
rust_code += "            _ => Err(\"Oh, no ...\")\n"
rust_code += "        }\n"
rust_code += "    }\n"

rust_code += """
    pub fn from_u8(n: u8) -> Result<Self, &'static str> {
        Status::new(n)
    }
"""

rust_code += """
    pub fn to_u8(&self) -> u8 {
        match *self {
"""
for i in range(len(status_set)):
    name_l = status_set[i]
    name_u = name_l[0].upper()+name_l[1:]
    rust_code += "            Status::%s => %d, \n" % (name_u, i)
rust_code += "        }\n"
rust_code += "    }\n"


rust_code += """
    pub fn from_str(s: &str) -> Result<Self, &'static str> {
        match s {
"""
for i in range(len(status_set)):
    name_l = status_set[i]
    name_u = name_l[0].upper()+name_l[1:]
    rust_code += "            \"%s\" => Ok(Status::%s), \n" % (name_l, name_u)
rust_code += "            _ => Err(\"Oh, no ...\")\n"
rust_code += "        }\n"
rust_code += "    }\n"


rust_code += """
    pub fn to_str(&self) -> &str {
        match *self {
"""
for i in range(len(status_set)):
    name_l = status_set[i]
    name_u = name_l[0].upper()+name_l[1:]
    rust_code += "            Status::%s => \"%s\", \n" % (name_u, name_l)
rust_code += "        }\n"
rust_code += "    }\n"


rust_code += """
    pub fn is_registry(&self) -> bool {
        match *self {
"""
for i in range(len(status_set)):
    name_l = status_set[i]
    name_u = name_l[0].upper()+name_l[1:]
    rust_code += "            Status::%s => %s, \n" % (name_u, str(name_l in registry_list).lower() )
rust_code += "        }\n"
rust_code += "    }\n"


rust_code += """
    pub fn is_state(&self) -> bool {
        self.is_registry() == false
    }
"""



rust_code += "}\n"

print(rust_code)