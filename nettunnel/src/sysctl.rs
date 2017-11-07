use std::process::Command;

pub fn enable_ipv4_forwarding() -> bool {
    let sysctl_arg = if cfg!(target_os = "linux") {
        "net.ipv4.ip_forward=1"
    } else if cfg!(target_os = "macos") {
        "net.inet.ip.forwarding=1"
    } else {
        unimplemented!()
    };

    let res = Command::new("sysctl")
        .arg("-w")
        .arg(sysctl_arg)
        .output()
        .expect(&format!("failed to execute `sysctl {}`", sysctl_arg));
    if res.status.success() == false {
        error!("Enabling IPv4 Forwarding:    [FAIL]");
        debug!("{}", String::from_utf8(res.stderr).unwrap());
    } else {
        info!("Enabling IPv4 Forwarding:    [OK]");
    }
    res.status.success()
}
