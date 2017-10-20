rust-netproxy 一个全平台支持可穿透防火墙的快速全局代理
=====================

## 特点
- ***不需要部署server端,只需要ssh账号/ssh key***
- 全局代理(理论上可以支持任何协议),有别于系统代理,不需要应用程序支持
- 高效IP自动路由,可以完整的区分国内和国外的流量
- 零配置,启动客户端即可


## 安装

### 准备工作
```
brew install python3
brew install rustup-init

rustup install nightly
rustup default nightly
```

### 编译
```   
python3 scripts/sync.py
python3 scripts/parse.py
python3 scripts/codegen.py

cargo run --bin dns
cargo run --bin ifaces

cargo run --bin ssh
cargo run --bin socks
cargo run --bin timezone

# Apple XNU libpf
cargo run --bin pf
# Apple XNU
cargo run --bin tun
```

### 参考引用
[TUN/TAP](https://en.wikipedia.org/wiki/TUN/TAP)

### 感谢 
