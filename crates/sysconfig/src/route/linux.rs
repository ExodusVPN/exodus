use libc;

// route flags
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/route.h
pub const RTF_UP: libc::c_ushort        = 0x0001;     // route usable
pub const RTF_GATEWAY: libc::c_ushort   = 0x0002;     // destination is a gateway
pub const RTF_HOST: libc::c_ushort      = 0x0004;     // host entry (net otherwise) 
pub const RTF_REINSTATE: libc::c_ushort = 0x0008;     // reinstate route after tmout
pub const RTF_DYNAMIC: libc::c_ushort   = 0x0010;     // created dyn. (by redirect)
pub const RTF_MODIFIED: libc::c_ushort  = 0x0020;     // modified dyn. (by redirect)
pub const RTF_MTU: libc::c_ushort       = 0x0040;     // specific MTU for this route
pub const RTF_MSS: libc::c_ushort       = RTF_MTU;    // Compatibility :-(
pub const RTF_WINDOW: libc::c_ushort    = 0x0080;     // per route window clamping
pub const RTF_IRTT: libc::c_ushort      = 0x0100;     // Initial round trip time
pub const RTF_REJECT: libc::c_ushort    = 0x0200;     // Reject route


// This structure gets passed by the SIOCADDRT and SIOCDELRT calls.
#[repr(C)]
pub struct rtentry {
    pub rt_pad1:    libc::c_ulong,
    pub rt_dst:     libc::sockaddr,   // target address
    pub rt_gateway: libc::sockaddr,   // gateway addr (RTF_GATEWAY)
    pub rt_genmask: libc::sockaddr,   // target network mask (IP)
    pub rt_flags:   libc::c_ushort,
    pub rt_pad2:    libc::c_short,
    pub rt_pad3:    libc::c_ulong,
    pub rt_pad4:    *const libc::c_void,
    pub rt_metric:  libc::c_short,    // +1 for binary compatibility!
    
    // char __user *rt_dev
    // pub rt_dev: *const ,           // forcing the device at add
    
    pub rt_mtu: libc::c_ulong,        // per route MTU/Window
    // pub rt_mss: rt_mtu,            // Compatibility :-(
    pub rt_window: libc::c_ulong,     // Window clamping
    pub rt_irtt: libc::c_ushort,      // Initial RTT
}