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

macOS:

.. code:: bash
    
    brew install rustup-init
    brew install FiloSottile/musl-cross/musl-cross

    rustup-init --default-toolchain nightly -y
    rustup toolchain install nightly
    rustup default nightly
    rustup show

    rustup target list
    # Unix
    rustup target add x86_64-apple-darwin
    rustup target add x86_64-apple-ios
    rustup target add armv7-apple-ios
    rustup target add armv7s-apple-ios
    rustup target add aarch64-apple-ios
    rustup target add x86_64-sun-solaris
    rustup target add x86_64-unknown-freebsd
    rustup target add x86_64-unknown-netbsd

    # Linux
    rustup target add x86_64-unknown-linux-gnu
    rustup target add x86_64-unknown-linux-musl
    rustup target add x86_64-linux-android
    rustup target add x86_64-unknown-fuchsia
    rustup target add armv7-linux-androideabi
    rustup target add aarch64-linux-android
    
    # Windows
    rustup target add x86_64-pc-windows-gnu

    # Other
    rustup target add x86_64-unknown-redox


    cd nettunnel
    cargo build
    cd ../

    # Run VPN server
    target/debug/nettunnel-server
    # Run VPN Client
    target/debug/nettunnel-client

    ifconfig
    

Debian 9:

.. code:: bash
    
    sudo apt install build-essential libssl-dev make cmake clang gcc

    wget https://static.rust-lang.org/rustup.sh
    chmod +x rustup.sh
    ./rustup.sh --channel=nightly

    git clone https://github.com/LuoZijun/exodus.git
    cd exodus
    cargo build
    
    ip addr



    