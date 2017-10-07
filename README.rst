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

    cargo run --dns
    cargo run --ssh
    cargo run --socks
    cargo run --timezone