#!/bin/bash
mkdir -p ./src/bin 
cp ./*.rs ./src/bin
cargo build
cargo run --bin GF-GCM
cargo run --bin rsa
