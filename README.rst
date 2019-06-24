Exodus: Ciphertext and plaintext
====================================

.. image:: https://badges.gitter.im/Join%20Chat.svg
    :alt: Join the chat at https://gitter.im/luozijun/exodus
    :target: https://gitter.im/luozijun/exodus?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge

.. image:: https://img.shields.io/badge/Telegram%20Group-https%3A%2F%2Ft.me%2FExodusProject-blue.svg
    :alt: Join the chat at https://t.me/ExodusProject
    :target: https://t.me/ExodusProject



.. image:: assets/logo.jpg
    :scale: 10 %


:Date: 10/03 2017

.. contents::


平台支持
-------------------

VPN Server:

*   Linux > 3.0

VPN Client:

*   macOS >= 10.13
*   Linux > 3.0


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
