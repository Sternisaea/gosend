#!/bin/bash

version_tag=$(git describe --tags --exact-match $(git rev-parse HEAD) 2>/dev/null)
if [ -z "$version_tag" ]; then
  echo "Error: No tags found for the current commit."
  exit 1
fi

set -e

platforms=(
  "linux/386"
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/386"
  "windows/amd64"
  "windows/arm64"
  "freebsd/386"
  "freebsd/amd64"
  "freebsd/arm64"
  "netbsd/386"
  "netbsd/amd64"
  "netbsd/arm64"
  "openbsd/386"
  "openbsd/amd64"
  "openbsd/arm64"
)

OUTPUT_DIR="bin"
mkdir -p $OUTPUT_DIR

MD5SUM_FILE="$OUTPUT_DIR/md5sum.txt"
> "$MD5SUM_FILE"

for platform in "${platforms[@]}"; do
  IFS="/" read -r GOOS GOARCH <<< "$platform"
  echo "Building gosend $GOOS $GOARCH"
  output_name="$OUTPUT_DIR/gosend"
  if [ "$GOOS" = "windows" ]; then
    output_name+=".exe"
  fi
  env GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-X main.version=${version_tag}" -o "$output_name" src/cmd/gosend.go
  compressed_name="$OUTPUT_DIR/gosend-$GOOS-$GOARCH-$version_tag"
  case "$GOOS" in
    windows)
      compressed_name+=".zip"
      zip -j -q "$compressed_name" "$output_name"
      ;;
    freebsd)
      compressed_name+=".tar.xz"
      tar -cJf "$compressed_name" -C "$OUTPUT_DIR" "$(basename "$output_name")"
      ;;
    darwin)
      compressed_name=$(echo "$compressed_name" | sed 's/darwin/macos/').tar.gz
      tar -czf "$compressed_name" -C "$OUTPUT_DIR" "$(basename "$output_name")"
      ;;
    *)
      compressed_name+=".tar.gz"
      tar -czf "$compressed_name" -C "$OUTPUT_DIR" "$(basename "$output_name")"
      ;;
  esac
  md5sum "$compressed_name" | awk '{print $1, " ", "'"$compressed_name"'"}' >> "$MD5SUM_FILE"
  rm "$output_name"
done

echo "Build completed."