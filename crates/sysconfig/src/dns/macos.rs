// https://developer.apple.com/documentation/systemconfiguration
// https://developer.apple.com/library/content/documentation/Networking/Conceptual/SystemConfigFrameworks/SC_UnderstandSchema/SC_UnderstandSchema.html#//apple_ref/doc/uid/TP40001065-CH203-CHDEJACB

use libc;

use core_foundation::base::{CFType, CFTypeRef, TCFType, TCFTypeRef};
use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::string::{CFString, CFStringRef};
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef, CFMutableDictionary};
use core_foundation::base::{CFAllocatorRef, kCFAllocatorDefault, Boolean};
use system_configuration::dynamic_store::SCDynamicStoreBuilder;

use std::fmt;
use std::mem;
use std::ptr;
use std::net::IpAddr;


const SESSION_NAME: &str = "ExodusVPN";

pub type __SCNetworkInterface  = libc::c_void;
pub type SCNetworkInterfaceRef = *const __SCNetworkInterface;
pub type SCBondInterfaceRef    = SCNetworkInterfaceRef;
pub type SCVLANInterfaceRef    = SCNetworkInterfaceRef;

pub type __SCBondStatus  = libc::c_void;
pub type SCBondStatusRef = *const __SCBondStatus;

pub type __SCNetworkProtocol  = libc::c_void;
pub type SCNetworkProtocolRef = *const __SCNetworkProtocol;

pub type __SCNetworkService  = libc::c_void;
pub type SCNetworkServiceRef = *const __SCNetworkService;

pub type __SCNetworkSet  = libc::c_void;
pub type SCNetworkSetRef = *const __SCNetworkSet;

pub type __SCPreferences  = libc::c_void;
pub type SCPreferencesRef = *const __SCPreferences;


#[link(name = "SystemConfiguration", kind = "framework")]
extern "C" {
    pub fn SCPreferencesCreate(allocator: CFAllocatorRef,
                               name: CFStringRef,
                               prefsID: CFStringRef) -> SCPreferencesRef;
    pub fn SCNetworkServiceCopyAll(prefs: SCPreferencesRef) -> CFArrayRef;
    pub fn SCNetworkServiceCopy(prefs: SCPreferencesRef,
                                serviceID: CFStringRef) -> SCNetworkServiceRef;
    pub fn SCNetworkServiceGetEnabled(service: SCNetworkServiceRef) -> Boolean;
    pub fn SCNetworkServiceGetInterface(service: SCNetworkServiceRef) -> SCNetworkInterfaceRef;
    pub fn SCNetworkServiceGetName(service: SCNetworkServiceRef) -> CFStringRef;
    pub fn SCNetworkServiceGetServiceID(service: SCNetworkServiceRef) -> CFStringRef;
    pub fn SCNetworkSetGetServiceOrder(set: SCNetworkSetRef) -> CFArrayRef;
    pub fn SCNetworkSetCopyServices(set: SCNetworkSetRef) -> CFArrayRef;
    pub fn SCNetworkSetCopyCurrent(prefs:SCPreferencesRef) -> SCNetworkSetRef;

    pub fn SCNetworkInterfaceCopyAll() -> CFArrayRef;
    pub fn SCNetworkInterfaceCopyMTU(interface: SCNetworkInterfaceRef, 
                                     mtu_cur: *mut libc::c_int,
                                     mtu_min: *mut libc::c_int,
                                     mtu_max: *mut libc::c_int) -> Boolean;
    pub fn SCNetworkInterfaceCopyMediaOptions(interface: SCNetworkInterfaceRef,
                                              urrent: *mut CFDictionaryRef,
                                              active: *mut CFDictionaryRef,
                                              available: *mut CFArrayRef,
                                              filter: Boolean) -> Boolean;
    pub fn SCNetworkInterfaceGetBSDName(interface: SCNetworkInterfaceRef) -> CFStringRef;
    pub fn SCNetworkInterfaceGetInterfaceType(interface: SCNetworkInterfaceRef) -> CFStringRef;
    pub fn SCNetworkInterfaceGetHardwareAddressString(interface: SCNetworkInterfaceRef) -> CFStringRef;
    
    pub fn SCNetworkInterfaceGetConfiguration(interface: SCNetworkInterfaceRef) -> CFDictionaryRef;
    pub fn SCNetworkInterfaceGetExtendedConfiguration(interface: SCNetworkInterfaceRef,
                                                      extendedType: CFStringRef) -> CFDictionaryRef;

    pub fn SCNetworkInterfaceSetConfiguration(interface: SCNetworkInterfaceRef,
                                              config: CFDictionaryRef) -> Boolean;
    pub fn SCNetworkInterfaceSetExtendedConfiguration(interface: SCNetworkInterfaceRef,
                                                      extendedType: CFStringRef,
                                                      config: CFDictionaryRef) -> Boolean;
}



// State:/Network/Interface
// State:/Network/Global/IPv4
// State:/Network/Service/F9E76868-D156-4195-901E-6CD729298651/IPv4
// State:/Network/Service/F9E76868-D156-4195-901E-6CD729298651/DHCP
// State:/Network/Service/F9E76868-D156-4195-901E-6CD729298651/DNS
// State:/Network/Service/F9E76868-D156-4195-901E-6CD729298651/Interface

// State:/Network/Global/IPv4
// State:/Network/Global/DNS
// State:/Network/Global/NetInfo
// State:/Network/Global/Proxies

// State:/Network/Service/.*/DNS
// Setup:/Network/Service/.*/DNS

#[derive(Debug)]
pub struct NetworkGlobal {
    pub service: SCNetworkService,
    pub interface: SCNetworkInterface,
    pub router: Option<IpAddr>
}

impl NetworkGlobal {
    /// 需要 Root 权限
    pub fn set_global_dns(&self, addrs: &[ IpAddr ]) -> Result<bool, std::io::Error> {
        // https://00f.net/2011/08/14/programmatically-changing-network-configuration-on-osx/
        if unsafe { libc::getuid() } != 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }

        let store = SCDynamicStoreBuilder::new(SESSION_NAME).build();

        let mut dns_dictionary = CFMutableDictionary::new();
        let d_keys = CFString::from_static_string("ServerAddresses");
        let d_values = CFArray::from_CFTypes(
                            &addrs
                            .iter()
                            .map(|s| CFString::new(&format!("{}", s)) )
                            .collect::<Vec<CFString>>());
        
        dns_dictionary.add(
            &d_keys.as_concrete_TypeRef().as_void_ptr(),
            &d_values.as_concrete_TypeRef().as_void_ptr());
        let dns_dictionary = dns_dictionary.as_CFType().downcast::<CFDictionary>().unwrap();

        let pattern = "State:/Network/(Service/.+|Global)/DNS";
        match store.get_keys(pattern) {
            Some(keys) => {
                for item in keys.iter() {
                    store.set(item.clone(), dns_dictionary.clone());
                }

                Ok(true)
            },
            None => Ok(false),
        }
    }
}

pub fn get_network_global() -> NetworkGlobal {
    let store = SCDynamicStoreBuilder::new(SESSION_NAME).build();
    
    let key = "State:/Network/Global/IPv4";

    let mut service: Option<SCNetworkService> = None;
    let mut interface: Option<SCNetworkInterface> = None;
    let mut router: Option<IpAddr> = None;

    if let Some(value) = store.get(key.clone()) {
        if let Some(dict) = value.downcast::<CFDictionary>() {
            let d_key = CFString::from_static_string("PrimaryService").as_concrete_TypeRef().as_void_ptr();
            if let Some(val) = dict.find(d_key) {
                let value = unsafe { CFType::wrap_under_get_rule(*val) };
                if let Some(service_id) = value.downcast::<CFString>() {
                    let service_id = service_id.to_string();

                    for _service in list_network_services(){
                        if _service.id()  == service_id {
                            service = Some(_service);
                            break;
                        }
                    }
                }
            }
        }
    }

    if let Some(value) = store.get(key.clone()) {
        if let Some(dict) = value.downcast_into::<CFDictionary>() {
            let d_key = CFString::from_static_string("PrimaryInterface").as_concrete_TypeRef().as_void_ptr();
            if let Some(val) = dict.find(d_key) {
                let value = unsafe { CFType::wrap_under_get_rule(*val) };
                if let Some(ifname) = value.downcast::<CFString>() {
                    for iface in list_network_interfaces(){
                        let bsd_name = iface.bsd_name();
                        if bsd_name.is_some() && bsd_name.unwrap() == ifname.to_string() {
                            interface = Some(iface);
                            break;
                        }
                    }
                }
            }
        }
    }

    if let Some(value) = store.get(key) {
        if let Some(dict) = value.downcast_into::<CFDictionary>() {
            let d_key = CFString::from_static_string("Router").as_concrete_TypeRef().as_void_ptr();
            if let Some(val) = dict.find(d_key) {
                let value = unsafe { CFType::wrap_under_get_rule(*val) };
                if let Some(router_str) = value.downcast::<CFString>() {
                    let router_str = router_str.to_string();
                    match router_str.parse::<IpAddr>() {
                        Ok(router_ip) => {
                            router = Some(router_ip);
                        }
                        _ => { }
                    }
                }
            }
        }
    }

    if service.is_none() || interface.is_none() {
        panic!("Get Default NetworkService And NetworkInterface failure.");
    }

    NetworkGlobal {
        service: service.unwrap(),
        interface: interface.unwrap(),
        router: router
    }
}

pub struct SCNetworkService(pub SCNetworkServiceRef);
pub struct SCNetworkInterface(pub SCNetworkInterfaceRef);

#[derive(Debug)]
pub struct Dns {
    pub default_domain_name: Option<String>,
    pub default_addrs: Option<Vec<IpAddr>>,
    pub manually_specifying_domain_name: Option<String>,
    pub manually_specifying_addrs: Option<Vec<IpAddr>>,
}

impl SCNetworkService {

    pub fn id(&self) -> String {
        unsafe { CFString::wrap_under_get_rule( SCNetworkServiceGetServiceID( self.0 ) ) }.to_string()
    }

    pub fn name(&self) -> String {
        unsafe { CFString::wrap_under_get_rule( SCNetworkServiceGetName( self.0 ) ) }.to_string()
    }

    pub fn enabled(&self) -> bool {
        let ret = unsafe { SCNetworkServiceGetEnabled( self.0 ) };
        ret == 1
    }

    pub fn dns(&self) -> Dns {
        let store = SCDynamicStoreBuilder::new(SESSION_NAME).build();

        let mut default_domain_name: Option<String> = None;
        let mut default_addrs: Option<Vec<IpAddr>> = None;
        let mut manually_specifying_domain_name: Option<String> = None;
        let mut manually_specifying_addrs: Option<Vec<IpAddr>> = None;

        if let Some(value) = store.get(CFString::new(&format!("State:/Network/Service/{}/DNS", self.id()))) {
            if let Some(dict) = value.downcast_into::<CFDictionary>() {
                let d_key = CFString::from_static_string("DomainName").as_concrete_TypeRef().as_void_ptr();
                if let Some(domain_name) = dict.find(d_key) {
                    let domain_name = unsafe { CFType::wrap_under_get_rule(*domain_name) };
                    if let Some(domain_name) = domain_name.downcast::<CFString>() {
                        default_domain_name = Some(domain_name.to_string());
                    }
                }

                let d_key = CFString::from_static_string("ServerAddresses").as_concrete_TypeRef().as_void_ptr();
                if let Some(addrs) = dict.find(d_key) {
                    let addrs = unsafe { CFType::wrap_under_get_rule(*addrs) };
                    if let Some(addrs) = addrs.downcast::<CFArray<CFTypeRef>>() {
                        let mut temp = Vec::new();
                        for addr in addrs.iter() {
                            if let Ok(ip_addr) = unsafe { CFString::wrap_under_get_rule(*addr as *const _).to_string().parse::<IpAddr>() } {
                                temp.push(ip_addr);
                            }
                        }

                        if temp.len() > 0 {
                            default_addrs = Some(temp);
                        }
                    }
                }
            }
        }

        if let Some(value) = store.get(CFString::new(&format!("Setup:/Network/Service/{}/DNS", self.id()))) {
            if let Some(dict) = value.downcast_into::<CFDictionary>() {
                if let Some(domain_name) = dict.find(CFString::from_static_string("DomainName").as_concrete_TypeRef().as_void_ptr()) {
                    let domain_name = unsafe { CFType::wrap_under_get_rule(*domain_name) };
                    if let Some(domain_name) = domain_name.downcast::<CFString>() {
                        manually_specifying_domain_name = Some(domain_name.to_string());
                    }
                }

                if let Some(addrs) = dict.find(CFString::from_static_string("ServerAddresses").as_concrete_TypeRef().as_void_ptr()) {
                    let addrs = unsafe { CFType::wrap_under_get_rule(*addrs) };
                    if let Some(addrs) = addrs.downcast::<CFArray<CFTypeRef>>() {
                        let mut temp = Vec::new();
                        for addr in addrs.iter() {
                            if let Ok(ip_addr) = unsafe { CFString::wrap_under_get_rule(*addr as *const _).to_string().parse::<IpAddr>() } {
                                temp.push(ip_addr);
                            }
                        }

                        if temp.len() > 0 {
                            manually_specifying_addrs = Some(temp);
                        }
                    }
                }
            }
        }

        Dns {
            default_domain_name: default_domain_name,
            default_addrs: default_addrs,
            manually_specifying_domain_name: manually_specifying_domain_name,
            manually_specifying_addrs: manually_specifying_addrs,
        }
    }

    /// 需要 ROOT 权限执行
    pub fn set_dns(&self, addrs: &[ IpAddr ]) -> Result<bool, std::io::Error> {
        // https://00f.net/2011/08/14/programmatically-changing-network-configuration-on-osx/
        // sudo networksetup -getdnsservers "Wi-Fi"
        // sudo networksetup -setdnsservers "Wi-Fi" "Empty"
        if unsafe { libc::getuid() } != 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        }

        let store = SCDynamicStoreBuilder::new(SESSION_NAME).build();

        let mut dns_dictionary = CFMutableDictionary::new();
        let d_keys = CFString::from_static_string("ServerAddresses");
        let d_values = CFArray::from_CFTypes(
                            &addrs
                            .iter()
                            .map(|s| CFString::new(&format!("{}", s)) )
                            .collect::<Vec<CFString>>());
        
        dns_dictionary.add(
            &d_keys.as_concrete_TypeRef().as_void_ptr(),
            &d_values.as_concrete_TypeRef().as_void_ptr());
        let dns_dictionary = dns_dictionary.as_CFType().downcast::<CFDictionary>().unwrap();
        
        let key = format!("Setup:/Network/Service/{}/DNS", self.id());
        
        Ok(store.set(key.as_ref(), dns_dictionary))
    }

    pub fn interface(&self) -> Option<SCNetworkInterface> {
        let pinterface = unsafe { SCNetworkServiceGetInterface( self.0 ) };
        if pinterface.is_null() {
            None
        } else {
            Some(SCNetworkInterface( pinterface ))
        }
    }
}

impl fmt::Display for SCNetworkService {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Debug for SCNetworkService {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
            "SCNetworkService{{ id: {:?}, name: {:?}, enabled: {}, interface: {:?} }}",
            self.id(),
            self.name(),
            self.enabled(),
            self.interface())
    }
}


impl SCNetworkInterface {
    pub fn mtu(&self) -> Option<(u32, u32, u32)> {
        let mut current = 0i32;
        let mut min = 0i32;
        let mut max = 0i32;

        let _ret_code = unsafe { SCNetworkInterfaceCopyMTU(self.0, &mut current, &mut min, &mut max) };
        if _ret_code == 0 {
            None
        } else {
            Some((current as u32, min as u32, max as u32))
        }
    }

    pub fn bsd_name(&self) -> Option<String> {
        unsafe {
            let pstr = SCNetworkInterfaceGetBSDName(self.0);
            if pstr.is_null() {
                None
            } else {
                Some(CFString::wrap_under_get_rule( pstr ).to_string())
            }
        }
    }

    pub fn type_(&self) -> Option<String> {
        unsafe { 
            let pstr = SCNetworkInterfaceGetInterfaceType(self.0);
            if pstr.is_null() {
                None
            } else {
                Some(CFString::wrap_under_get_rule( pstr ).to_string())
            }
        }
    }

    pub fn hwaddr(&self) -> Option<String> {
        unsafe { 
            let pstr = SCNetworkInterfaceGetHardwareAddressString(self.0);
            if pstr.is_null() {
                None
            } else {
                Some(CFString::wrap_under_get_rule( pstr ).to_string())
            }
        }
    }

    pub fn config(&self) -> Option<CFDictionary> {
        unsafe {
            let config_ptr = SCNetworkInterfaceGetConfiguration(self.0);
            if config_ptr.is_null() {
                None
            } else {
                Some(CFDictionary::wrap_under_get_rule( config_ptr ))
            }
        }
    }
}

impl fmt::Display for SCNetworkInterface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Debug for SCNetworkInterface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mtu = self.mtu();
        let mtu_fmt = if mtu.is_none() {
            format!("None")
        } else {
            let mtu = mtu.unwrap();
            format!("{{cur: {}, min: {}, max: {} }}", mtu.0, mtu.1, mtu.2)
        };

        write!(f,
            "SCNetworkInterface{{ mtu: {}, bsd_name: {:?}, type: {:?}, hwaddr: {:?}, config: {:?} }}", 
            mtu_fmt,
            self.bsd_name(),
            self.type_(),
            self.hwaddr(),
            self.config())
    }
}

pub fn list_network_services_order() -> Vec<SCNetworkService> {
    let prefs = unsafe { SCPreferencesCreate(kCFAllocatorDefault, 
                                             CFString::from_static_string(SESSION_NAME).as_concrete_TypeRef(),
                                             ptr::null()) };
    let netset = unsafe { SCNetworkSetCopyCurrent(prefs) };

    let array: CFArray<SCNetworkServiceRef> = unsafe { CFArray::wrap_under_get_rule( SCNetworkSetGetServiceOrder(netset) ) };
    let mut services = Vec::new();

    for id in array.get_all_values().iter() {
        let pid: CFStringRef = unsafe { mem::transmute(*id) };
        let pservice: SCNetworkServiceRef = unsafe { SCNetworkServiceCopy(prefs, pid) };
        services.push(SCNetworkService(pservice));
    }

    services
}

pub fn list_network_services() -> Vec<SCNetworkService> {
    let prefs = unsafe { SCPreferencesCreate(kCFAllocatorDefault,
                                             CFString::from_static_string(SESSION_NAME).as_concrete_TypeRef(),
                                             ptr::null()) };
    let array: CFArray<SCNetworkServiceRef> = unsafe { CFArray::wrap_under_get_rule(SCNetworkServiceCopyAll(prefs)) };
    array.get_all_values()
            .iter()
            .map(|service_ptr| SCNetworkService(*service_ptr) )
            .collect::<Vec<SCNetworkService>>()

}

pub fn list_network_interfaces() -> Vec<SCNetworkInterface> {
    let array: CFArray<SCNetworkInterfaceRef> = unsafe { CFArray::wrap_under_get_rule(SCNetworkInterfaceCopyAll()) };
    array.get_all_values()
        .iter()
        .map(|interface_ptr| SCNetworkInterface(*interface_ptr) )
        .collect::<Vec<SCNetworkInterface>>()
}

