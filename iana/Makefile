
data/:
	mkdir -p data

# data/country_codes.json data/records.json: data/delegated-afrinic-latest.md5 data/delegated-arin-extended-latest \
# 	data/delegated-lacnic-latest data/delegated-ripencc-latest.md5 data/delegated-apnic-extended-latest \
# 	data/delegated-arin-extended-latest.md5 data/delegated-lacnic-latest.md5 data/delegated-afrinic-extended-latest \
# 	data/delegated-apnic-extended-latest.md5 data/delegated-iana-latest data/delegated-ripencc-extended-latest \
# 	data/delegated-afrinic-extended-latest.md5 data/delegated-apnic-latest data/delegated-lacnic-extended-latest \
# 	data/delegated-ripencc-extended-latest.md5 data/delegated-afrinic-latest data/delegated-apnic-latest.md5 \
# 	data/delegated-lacnic-extended-latest.md5 data/delegated-ripencc-latest:
# 	python3 scripts/parse.py

# # data/delegated-afrinic-latest.md5 data/delegated-arin-extended-latest data/delegated-lacnic-latest \
# # 	data/delegated-ripencc-latest.md5 data/delegated-apnic-extended-latest data/delegated-arin-extended-latest.md5 \
# # 	data/delegated-lacnic-latest.md5 data/delegated-afrinic-extended-latest data/delegated-apnic-extended-latest.md5 \
# # 	data/delegated-iana-latest data/delegated-ripencc-extended-latest data/delegated-afrinic-extended-latest.md5 \
# # 	data/delegated-apnic-latest data/delegated-lacnic-extended-latest data/delegated-ripencc-extended-latest.md5 \
# # 	data/delegated-afrinic-latest data/delegated-apnic-latest.md5 data/delegated-lacnic-extended-latest.md5 \
# # 	data/delegated-ripencc-latest:
# # 	mkdir -p data
# # 	python3 scripts/sync.py

.PHONY: sync
sync:
	python3 scripts/sync.py

.PHONY: parse
parse:
	python3 scripts/parse.py

.PHONY: gen
gen:
	python3 scripts/country_codegen.py > src/country.rs
	python3 scripts/ipn_status_codegen.py > src/number/status.rs
	python3 scripts/registry_codegen.py > src/number/registry.rs
	python3 scripts/ipdb_codegen.py

.PHONY: default
default: sync parse gen


.PHONY: build
build:
	cargo build


