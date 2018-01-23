#!/bin/bash

# cargo install bindgen
# cargo install rustfmt

bindgen --rustfmt-bindings  --no-layout-tests --generate-inline-functions bitfield.h > bitfield.rs
rustfmt --force bitfield.rs
