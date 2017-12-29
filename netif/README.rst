netif
========

:Date: 12/25 2017


.. contents::

like `shemminger/iproute2 <https://github.com/shemminger/iproute2>`_

Run
------

.. code:: bash
    
    cargo build --bin ip

    # like iproute2
    target/debug/ip link
    target/debug/ip neigh
    target/debug/ip route
    
    # bsd `bpf` raw packet read and write.
    cargo run --bin bpf
    sudo target/debug/bpf
