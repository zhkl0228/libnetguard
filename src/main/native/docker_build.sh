#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESOURCES_DIR="$SCRIPT_DIR/../resources/natives"
IMAGE_NAME="netguard-native-builder"

CLEAN=false
while [[ "$1" == --* ]]; do
    case "$1" in
        --clean) CLEAN=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

cd "$SCRIPT_DIR"

build_linux() {
    local platform=$1
    local output_dir=$2

    echo "=== Building for $output_dir ($platform) ==="

    local docker_args=""
    if $CLEAN; then
        docker_args="--no-cache"
    fi

    docker build --platform "$platform" $docker_args -t "${IMAGE_NAME}-${output_dir}" .

    echo "Extracting libnetguard.so..."
    mkdir -p "$RESOURCES_DIR/$output_dir"
    CONTAINER_ID=$(docker create --platform "$platform" "${IMAGE_NAME}-${output_dir}")
    docker cp "$CONTAINER_ID:/build/jni/libnetguard.so" "$RESOURCES_DIR/$output_dir/libnetguard.so"
    docker rm "$CONTAINER_ID" > /dev/null

    echo "Done: $RESOURCES_DIR/$output_dir/libnetguard.so"
    ls -l "$RESOURCES_DIR/$output_dir/libnetguard.so"
    echo
}

TARGET=${1:-all}

case "$TARGET" in
    linux_64)
        build_linux linux/amd64 linux_64
        ;;
    linux_arm64)
        build_linux linux/arm64 linux_arm64
        ;;
    all)
        build_linux linux/amd64 linux_64
        build_linux linux/arm64 linux_arm64
        ;;
    *)
        echo "Usage: $0 [--clean] [linux_64|linux_arm64|all]"
        echo ""
        echo "Options:"
        echo "  --clean     Clean build (rebuild image from scratch)"
        echo ""
        echo "Targets:"
        echo "  linux_64    - Linux x86_64 (Docker)"
        echo "  linux_arm64 - Linux ARM64 (Docker)"
        echo "  all         - all Linux targets (default)"
        exit 1
        ;;
esac
