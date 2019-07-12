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

重写中 ...


运行
-------
    
请不要在 `生产环境` 部署和运行该程序！

.. code:: bash
    
    cd exodus
    # VPN Server
    sudo ./vpnd --tun-network 172.16.0.0/16

    # VPN Client
    sudo ./vpn --server-addr YOUR_VPN_SERVER_IPV4_ADDR:YOUR_VPN_SERVER_UDP_PORT --disable-crypto
