Exodus
====================================

.. image:: https://img.shields.io/badge/Telegram%20Group-https%3A%2F%2Ft.me%2FExodusProject-blue.svg
    :alt: Join the chat at https://t.me/ExodusProject
    :target: https://t.me/ExodusProject



:Date: 10/03 2017

.. contents::


平台支持
-------------------

VPN Server:

*   Linux > 3.0

VPN Client:

*   macOS >= 10.13
*   Linux > 3.0


IPV4 私有 IP 段
------------------

Private IPv4 addresses:

    10.0.0.0/8      10.0.0.0    – 10.255.255.255

    172.16.0.0/12   172.16.0.0  – 172.31.255.255

    192.168.0.0/16  192.168.0.0 – 192.168.255.255


状态
---------

系统网络配置组件(sysconfig/netlink/sysctl):

Linux 系统:

*   ✅ IP 转发控制 (相当于 `sysctl net.ipv4.conf.all.forwarding = 1` )
*   🔜 系统 DNS 设定 (相当于 `echo "nameserver 8.8.8.8" >> /etc/resolv.conf` )
*   ✅ netlink link list (相当于 `ip link list` )
*   ✅ netlink neigh list (相当于 `ip neigh list` )
*   ✅ netlink addr list (相当于 `ip addr list` )
*   ✅ 系统路由表缓存下载 (`相当于 `ip route list` )
*   ✅ 系统路由表删除操作 (`相当于 `ip route del` )
*   ✅ 系统路由表增加操作 (`相当于 `ip route add` )
*   ❌ 系统防火墙规则设定 (相当于 `iptables/nftables ...` )

macOS 系统:

*   ✅ IP 转发控制 (相当于 `sysctl net.ipv4.conf.all.forwarding = 1` )
*   ✅ 系统 DNS 设定 (相当于 `networksetup -setdnsservers "Wi-Fi" "8.8.8.8"` )
*   🔜 系统 ARP/NDP 缓存表下载 ( 相当于 `arp/ndp -an` )
*   ✅ 系统路由表缓存下载 (`相当于 `netstat -rn` )
*   ✅ 系统路由表删除操作 (`相当于 `route del` )
*   🔜 系统路由表增加操作 (`相当于 `route add` )
*   ❌ 系统防火墙规则设定 (相当于 `pfctl ...` )


运行
-------
    
请不要在 `生产环境` 部署和运行该程序！

.. code:: bash
    
    cd exodus
    # VPN Server
    sudo ./vpnd --tun-network 172.16.0.0/16

    # VPN Client
    sudo ./vpn --server-addr YOUR_VPN_SERVER_IPV4_ADDR:YOUR_VPN_SERVER_UDP_PORT --disable-crypto
