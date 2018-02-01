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


Platform Support
-------------------

VPN Server:

*   Linux > 3.0

VPN Client:

*   macOS >= 10.13
*   Linux > 3.0


Build
---------

macOS:

.. code:: bash
    
    # commandline tools: make, GCC, clang, perl, svn, git, size, strip, strings, libtool, cpp ...
    sudo xcode-select --install
    
    brew install git curl wget
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
    
    sudo apt install git curl wget clang pkg-config libssl-dev 
    sudo apt install build-essential make cmake

    wget https://static.rust-lang.org/rustup.sh
    chmod +x rustup.sh
    ./rustup.sh --channel=nightly

    git clone https://github.com/LuoZijun/exodus.git
    cd exodus
    cargo build --bin vpnd --release
    
    cp target/release/vpnd .


OpenWRT 17.01.4:

.. code:: bash
    
    wget "http://downloads.openwrt.org/releases/17.01.4/targets/x86/64/lede-17.01.4-x86-64-combined-ext4.img.gz"
    tar -xvjf lede-17.01.4-x86-64-combined-ext4.img.gz
    #dd if=lede-17.01.4-x86-64-combined-squashfs.img of=openwrt.img bs=100m conv=sync
    #VBoxManage convertfromraw --format VMDK openwrt.img openwrt.vmdk

    VBoxManage convertfromraw --format VMDK lede-17.01.4-x86-64-combined-ext4.img openwrt.vmdk
    VBoxManage clonehd "openwrt.vmdk" "openwrt.vdi" --format vdi
    VBoxManage modifyhd "openwrt.vdi" --resize 5120

    opkg update
    opkg install wget
    opkg install curl
    opkg install bash
    opkg install vim
    opkg install ca-certificates
    opkg install openssl-util

    touch ~/.bashrc
    echo "export SSL_CERT_DIR=/etc/ssl/certs" >> ~/.bashrc
    

Cross
---------

Host: GNU/Linux

.. code:: bash
    
    brew install qemu
    brew install docker

    docker pull japaric/x86_64-unknown-linux-gnu
    docker pull japaric/x86_64-unknown-linux-musl
    docker pull japaric/x86_64-unknown-freebsd
    docker pull japaric/x86_64-unknown-netbsd

    docker pull japaric/arm-unknown-linux-gnueabi
    docker pull japaric/arm-linux-androideabi
    docker pull japaric/armv7-unknown-linux-gnueabihf
    docker pull japaric/armv7-linux-androideabi

    docker pull japaric/aarch64-unknown-linux-gnu
    docker pull japaric/aarch64-linux-android

    docker pull japaric/mips-unknown-linux-gnu
    docker pull japaric/mipsel-unknown-linux-gnu
    docker pull japaric/mips64-unknown-linux-gnuabi64
    docker pull japaric/mips64el-unknown-linux-gnuabi64

    cargo install cross

    cross build --bin vpn --release 
    # For OpenWRT devices:
    #     mips-unknown-linux-uclibc (15.05 and older) 
    #     mips-unknown-linux-musl (post 15.05)
    #     x86_64-unknown-linux-musl (post 15.05)
    #     arm-unknown-linux-musl (post 15.05)
    #     armv7-unknown-linux-musl (post 15.05)
    cross build --bin vpn --target x86_64-unknown-linux-musl --release 



Run
-------

    WARN: Do Not Run `VPN Server` On a Production Env.


.. code:: bash

    cd exodus
    # VPN Server
    sudo ./vpnd --tun-network 172.16.0.0/16

    # VPN Client
    sudo ./vpn --server-addr YOUR_VPN_SERVER_IPV4_ADDR:YOUR_VPN_SERVER_UDP_PORT --disable-crypto
