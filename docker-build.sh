#!/usr/bin/env sh
set -eu

IMAGE_NAME="${IMAGE_NAME:-auto-server}"
TARGET="${TARGET:-x86_64-unknown-linux-musl}"

rustup target add "${TARGET}"
cargo build --release --locked --target "${TARGET}"

BIN_PATH="target/${TARGET}/release/auto-server"
STAGE_DIR="dist"
STAGE_BIN="${STAGE_DIR}/auto-server"

mkdir -p "${STAGE_DIR}"
cp "${BIN_PATH}" "${STAGE_BIN}"

docker build \
  -t "${IMAGE_NAME}:${TARGET}" \
  -f Dockerfile \
  .
