#!/bin/bash

set -e

OUTPUT_DIR="bin"
mkdir -p $OUTPUT_DIR

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
  "freebsd/arm"
  "freebsd/arm64"
  "netbsd/386"
  "netbsd/amd64"
  "netbsd/arm"
  "netbsd/arm64"
  "openbsd/386"
  "openbsd/amd64"
  "openbsd/arm"
  "openbsd/arm64"
)

MD5SUM_FILE="$OUTPUT_DIR/md5sum.txt"
> "$MD5SUM_FILE"

for platform in "${platforms[@]}"; do
  IFS="/" read -r GOOS GOARCH <<< "$platform"
  echo "Building gosend $GOOS $GOARCH"
  output_name="$OUTPUT_DIR/gosend"
  if [ "$GOOS" = "windows" ]; then
    output_name+=".exe"
  fi
  env GOOS=$GOOS GOARCH=$GOARCH go build -o "$output_name" src/cmd/gosend.go
  case "$GOOS" in
    windows)
      compressed_name="$OUTPUT_DIR/gosend-$GOOS-$GOARCH.zip"
      zip -j -q "$compressed_name" "$output_name"
      ;;
    freebsd)
      compressed_name="$OUTPUT_DIR/gosend-$GOOS-$GOARCH.tar.xz"
      tar -cJf "$compressed_name" -C "$OUTPUT_DIR" "$(basename "$output_name")"
      ;;
    darwin)
      compressed_name="$OUTPUT_DIR/gosend-macos-$GOARCH.tar.gz"
      tar -czf "$compressed_name" -C "$OUTPUT_DIR" "$(basename "$output_name")"
      ;;
    *)
      compressed_name="$OUTPUT_DIR/gosend-$GOOS-$GOARCH.tar.gz"
      tar -czf "$compressed_name" -C "$OUTPUT_DIR" "$(basename "$output_name")"
      ;;
  esac
  md5sum "$compressed_name" | awk '{print $1, " ", "'"$compressed_name"'"}' >> "$MD5SUM_FILE"
  rm "$output_name"
done

echo "Build completed."