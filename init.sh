#!/bin/bash
mkdir -p ./src/bin 
cp ./*.rs ./src/bin
cargo build
cargo run --bin gf-gcm
cargo run --bin rsa
