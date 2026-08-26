#!/usr/bin/env bash
# Builds and runs the Rust k256 comparison.
set -euo pipefail
cd "$(dirname "$0")"
cargo run --release
