#!/bin/bash
mkdir -p ./src/bin 
cp ./*.rs ./src/bin
cargo build --release
cargo run --bin gf-gcm -r
cargo run --bin rsa -r
cargo run --bin ploy1305 -r
