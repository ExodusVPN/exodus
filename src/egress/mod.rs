

#[derive(Debug, Clone)]
pub enum Egress {
    SSH
}

impl Egress {
    pub fn egresses() -> Vec<String>{
        vec!["SSH"]
    }
}