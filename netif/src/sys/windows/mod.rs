#![cfg(target_os = "windows")]
#![allow(non_camel_case_types, non_snake_case, dead_code)]

// IP Helper Reference ( NetInterface && routing table ）
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa366072(v=vs.85).aspx

// NDIS driver types
// https://docs.microsoft.com/en-us/windows-hardware/drivers/network/ndis-drivers


use libc;
use winapi;

pub use libc::{
    time_t,
};

pub use winapi::ctypes::{
    c_void, c_char, c_double, c_float, c_int, c_long, c_longlong, c_schar,
    c_short, c_uchar, c_uint, c_ulong, c_ulonglong, c_ushort, wchar_t,
};

pub use winapi::shared::minwindef::{
    // types
    ATOM, BOOL, BYTE, DWORD, FARPROC, FLOAT, GLOBALHANDLE,
    HFILE, HGLOBAL, HINSTANCE, HKEY, HKL, HLOCAL, HLSURF, 
    HMETAFILE, HMODULE, HRGN, HRSRC, HSPRITE, HSTR, HTASK, 
    HWINSTA, INT, LOCALHANDLE, LPARAM, LPBOOL, LPBYTE, LPCVOID, 
    LPDWORD, LPFILETIME, LPHANDLE, LPINT, LPLONG, LPVOID, LPWORD, 
    LRESULT, NEARPROC, PBOOL, PBYTE, PDWORD, PFILETIME, PFLOAT, 
    PHKEY, PINT, PROC, PSZ, PUCHAR, PUINT, PULONG, PUSHORT, 
    PWORD, SPHANDLE, UCHAR, UINT, ULONG, USHORT, WORD, WPARAM,
    // functions
    HIBYTE, HIWORD, LOBYTE, LOWORD, MAKELONG, MAKEWORD,
    // Constants
    FALSE, MAX_PATH, TRUE,
    // Structs
    FILETIME,
};

pub use winapi::shared::basetsd::{
    DWORD32, DWORD64, DWORD_PTR, HALF_PTR, HANDLE_PTR, INT8, INT16, 
    INT32, INT64, INT_PTR, KAFFINITY, LONG32, LONG64, LONG_PTR, 
    PDWORD32, PDWORD64, PDWORD_PTR, PHALF_PTR, PINT8, PINT16, PINT32, 
    PINT64, PINT_PTR, PKAFFINITY, PLONG32, PLONG64, PLONG_PTR, 
    POINTER_64_INT, PSIZE_T, PSSIZE_T, PUHALF_PTR, PUINT8, PUINT16, 
    PUINT32, PUINT64, PUINT_PTR, PULONG32, PULONG64, PULONG_PTR, 
    SHANDLE_PTR, SIZE_T, SSIZE_T, UHALF_PTR, UINT8, UINT16, UINT32, 
    UINT64, UINT_PTR, ULONG32, ULONG64, ULONG_PTR,
};

pub use winapi::shared::inaddr::{
    in_addr, in_addr_S_un, in_addr_S_un_b, in_addr_S_un_w,
    IN_ADDR, LPIN_ADDR, PIN_ADDR,
};
pub use winapi::shared::in6addr::{
    in6_addr, in6_addr_u,
    IN6_ADDR, LPIN6_ADDR, PIN6_ADDR
};
pub use winapi::shared::ntdef::{
    CSTRING, FLOAT128, GROUP_AFFINITY, LARGE_INTEGER, LARGE_INTEGER_s,
    LIST_ENTRY, LIST_ENTRY32, LIST_ENTRY64, LUID, OBJECTID, OBJECT_ATTRIBUTES,
    OBJECT_ATTRIBUTES32, OBJECT_ATTRIBUTES64, PROCESSOR_NUMBER, QUAD,
    RTL_BALANCED_NODE, RTL_BALANCED_NODE_s, RTL_BALANCED_NODE_u, SINGLE_LIST_ENTRY,
    SINGLE_LIST_ENTRY32, STRING, STRING32, STRING64, ULARGE_INTEGER, ULARGE_INTEGER_s,
    UNICODE_STRING, WNF_STATE_NAME,

    PVOID, PVOID64, PWCHAR, PCHAR
};

pub use winapi::shared::ws2def::{
    LPSOCKADDR, SOCKET_ADDRESS, PSOCKET_ADDRESS, SOCKADDR, ADDRESS_FAMILY,
    SOCKADDR_IN,
};

pub use winapi::um::winsock2::{
    accept, bind, closesocket, connect, gethostbyaddr, gethostbyname, gethostname,
    getpeername, getprotobyname, getprotobynumber, getservbyname, getservbyport,
    getsockname, getsockopt, h_errno, htond, htonf, htonl, htonll, htons, inet_addr,
    inet_ntoa, ioctlsocket, listen, ntohd, ntohf, ntohl, ntohll, ntohs, recv, 
    recvfrom, select, send, sendto, setsockopt, shutdown, socket,
};

pub use winapi::shared::winerror::{
    NO_ERROR, 
};


// https://msdn.microsoft.com/en-us/library/windows/desktop/ms738568(v=vs.85).aspx
pub const IFF_UP: libc::c_int = 0x00000001;
pub const IFF_BROADCAST: libc::c_int = 0x00000002;
pub const IFF_LOOPBACK: libc::c_int = 0x00000004;
pub const IFF_POINTTOPOINT: libc::c_int = 0x00000008;
pub const IFF_POINTOPOINT: libc::c_int = IFF_POINTTOPOINT;
pub const IFF_MULTICAST: libc::c_int = 0x00000010;


pub mod iphlpapi;



