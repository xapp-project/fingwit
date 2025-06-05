#!/bin/bash
# Host wrapper script to build AppImage in Docker

set -e

# Build the Docker image
echo "Building Docker image..."
docker build -f Dockerfile -t fingwit-appimage-builder .

# Run the build in Docker
echo "Running AppImage build in container..."
docker run --rm \
    -v "$PWD/..:/src" \
    -u "$(id -u):$(id -g)" \
    fingwit-appimage-builder

echo "Done! AppImage created: fingwit.AppImage"
