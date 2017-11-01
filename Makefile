
.PHONY: default
default: netproxy nettunnel


.PHONY: netproxy
netproxy:
	cd netproxy && cargo build


.PHONY: nettunnel
nettunnel:
	cd nettunnel && cargo build
