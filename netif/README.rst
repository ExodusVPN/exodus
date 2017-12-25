netif
========

:Date: 12/25 2017


.. contents::

like `shemminger/iproute2 <https://github.com/shemminger/iproute2>`_

Run
------

.. code:: bash
    
    # same as `ip addr`
    cargo run --bin interfaces
    # same as `ip neigh`
    cargo run --bin neigh
    # same as `ip route list`
    cargo run --bin route

    # bsd `bpf` raw packet read and write.
    cargo run --bin route
    sudo target/debug/bpf
    