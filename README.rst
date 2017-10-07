rust-netproxy
=====================

:Date: 10/03 2017

.. contents::


Build
--------

.. code:: bash
    
    brew install python3
    brew install rustup-init

    rustup install nightly
    rustup default nightly


.. code:: bash
    
    python3 scripts/sync.py
    python3 scripts/parse.py
    python3 scripts/codegen.py

    cargo run --bin dns
    cargo run --bin ifaces

    cargo run --bin ssh
    cargo run --bin socks
    cargo run --bin timezone