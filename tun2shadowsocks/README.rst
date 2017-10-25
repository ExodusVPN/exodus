tun2shadowsocks
==================


.. code:: bash

    tunnel

    mockingjay engress="shadowsocks" host="127.0.0.1:8388" passwd="mypassword" method="aes-256-cfb" timeout=300
    mockingjay engress="socks"       host="127.0.0.1:1080"

    mockingjay engress="ssh"         host="55.66.22.33.12:22" user="tunnel" paddwd="mypassword"
    mockingjay engress="ssh"         host="55.66.22.33.12:22" user="tunnel" prikey="~/.ssh/my_prikey.key"

    vpn host="55.66.22.33.12:9000" user="username" passwd="mypasswd"

