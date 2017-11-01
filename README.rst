Exodus: Ciphertext and plaintext
====================================

:Date: 10/03 2017

.. contents::


项目
--------

*   `netproxy <https://github.com/LuoZijun/exodus/tree/master/netproxy>`_  , 一个 全局TCP/UDP 代理实现
*   `nettunnel <https://github.com/LuoZijun/exodus/tree/master/nettunnel>`_ , 一个 VPN 实现


组件
---------

*   `iana <https://github.com/LuoZijun/exodus/tree/master/iana>`_ , 一个 IANA IP/DOMAIN 数据库实现
*   `netpacket <https://github.com/LuoZijun/exodus/tree/master/netpacket>`_ , 一个简单的网络包解析器实现
*   `netstack <https://github.com/LuoZijun/exodus/tree/master/netstack>`_ , 一个简单的网络栈实现
*   `taptun <https://github.com/LuoZijun/exodus/tree/master/taptun>`_ , 一个跨平台的 TAP/TUN 实现

编译
---------

.. code:: bash
    
    brew install rustup-init

    rustup-init --default-toolchain nightly -y
    rustup toolchain install nightly
    rustup default nightly
    rustup show

    rustup target list
    rustup target add x86_64-apple-darwin
    rustup target add x86_64-unknown-linux-gnu
    rustup target add x86_64-pc-windows-gnu
    rustup target add armv7-apple-ios
    rustup target add aarch64-apple-ios
    rustup target add aarch64-linux-android
    rustup target add armv7-linux-androideabi

    cd nettunnel
    cargo build
    cd ../

    # Run VPN server
    target/debug/nettunnel-server
    # Run VPN Client
    target/debug/nettunnel-client

    ifconfig
    

    