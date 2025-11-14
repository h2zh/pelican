#!/bin/bash
# Build Pelican for macOS from your Mac

cd /Users/hzhong/Documents/dev/pelican-0821/pelican

# Build for macOS (this will create dist/darwin_arm64/ or dist/darwin_amd64/)
make pelican-build

# Or if make doesn't work, build directly with Go:
cd cmd
GOOS=darwin GOARCH=arm64 go build -o pelican .

# Then test it
./pelican --version
./pelican mcp --help
