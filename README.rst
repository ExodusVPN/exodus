Exodus: Ciphertext and plaintext
====================================

.. image:: https://badges.gitter.im/Join%20Chat.svg
    :alt: Join the chat at https://gitter.im/luozijun/exodus
    :target: https://gitter.im/luozijun/exodus?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge

.. image:: https://img.shields.io/badge/Telegram%20Group-https%3A%2F%2Ft.me%2FExodusProject-blue.svg
    :alt: Join the chat at https://t.me/ExodusProject
    :target: https://t.me/ExodusProject



.. image:: assets/logo.jpg


:Date: 10/03 2017

.. contents::


Build
---------

macOS:

.. code:: bash
    
    brew install rustup-init
    brew install openssl

    rustup-init --default-toolchain nightly -y
    rustup toolchain install nightly
    rustup default nightly
    rustup show

    git clone https://github.com/LuoZijun/exodus.git
    cd exodus

    cargo build --bin vpn --release

    cp target/release/vpn .


Debian 9:

.. code:: bash
    
    sudo apt install build-essential libssl-dev make cmake clang gcc

    wget https://static.rust-lang.org/rustup.sh
    chmod +x rustup.sh
    ./rustup.sh --channel=nightly

    git clone https://github.com/LuoZijun/exodus.git
    cd exodus
    cargo build --bin vpnd --release
    
    cp target/release/vpnd .


Run
-------

    WARN: Do Not Run `VPN Server` On a Production Env.


.. code:: bash

    cd exodus
    # VPN Server
    sudo ./vpnd --tun-network 172.16.0.0/16

    # VPN Client
    sudo ./vpn --server-addr YOUR_VPN_SERVER_IPV4_ADDR:YOUR_VPN_SERVER_UDP_PORT --disable-crypto
