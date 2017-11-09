#![feature(non_ascii_idents)]

// https://icannwiki.org
// https://www.icann.org/resources/pages/tlds-2012-02-25-en
// https://github.com/rushmorem/publicsuffix

pub mod punycode;


/// List of Internet top-level domains
/// 
/// https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains
#[derive(Debug, PartialEq, Eq)]
pub enum Kind {
    Generic,
    Sponsored,
    GenericRestricted,
    Infrastructure,
    CountryCode,
    // ICANN-era generic top-level domains
    // Internationalized generic top-level domains
    // Geographic top-level domains
    // Internationalized geographic top-level domains
    // Brand top-level domains
    // Internationalized brand top-level domains
    // Special-Use Domains
    //     IDN Test TLDs
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq)]
pub enum TopLevelDomain {
    /// generic
    COM,
    INFO,
    NET,
    ORG,
    /// sponsored
    AERO,
    ASIA,
    CAT,
    COOP,
    EDU,
    GOV,
    INT,
    JOBS,
    MLI,
    MOBI,
    TEL,
    TRAVEL,
    XXX,

    /// generic restricted
    BIZ,
    NAME,
    PRO,

    /// infrastructure
    ARPA,

    /// Country Code with alphabet (ccTLD)
    CN
    COM_CN,

    UK,
    CO_UK,

    /// Internationalized country code with non-alphabetic
    中国,
    中國,
    香港,

}

impl TopLevelDomain {
    pub fn is_generic_top_level(&self) -> bool {
        true
    }
    pub fn is_sponsored_top_level(&self) -> bool {
        true
    }
    pub fn is_generic_restricted_top_level(&self) -> bool {
        true
    }
    pub fn is_infrastructure_top_level(&self) -> bool {
        true
    }    
    pub fn is_country_code_top_level(&self) -> bool {
        true
    }

    // pub fn abs_level(&self) -> bool {

    // }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Domain {
    subdomain          : Option<String>,
    second_level_domain: String,
    top_level_domain   : TopLevelDomain
}

impl Domain {
    pub fn new(subdomain: &str, 
               second_level_domain: &str, 
               top_level_domain: TopLevelDomain) -> Result<Self, &'static str>{
        Ok(Domain{
            subdomain: Some(subdomain.to_string()),
            second_level_domain: second_level_domain.to_string(),
            top_level_domain: top_level_domain
        })
    }
    pub fn abstract_level(&self) -> bool {
        true
    }
}


fn main(){
    let r = Domain::new("www", "github", TopLevelDomain::中国);
    println!("{:?}", r);

    println!("{:?}", punycode::encode("中国"));
    println!("{:?}", punycode::encode("baidu中国"));

    println!("{:?}", punycode::decode("fiqs8s"));
}


