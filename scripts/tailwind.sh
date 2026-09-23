#!/bin/sh
# Compile src/static/tailwind.css from src/static/tailwind.input.css.
#
# Runs the Tailwind CSS standalone CLI at a pinned release, so the stylesheet is
# reproducible without Node or an npm tree. The CLI is downloaded once into
# target/ and checked against the SHA-256 Tailwind publishes for the release
# before it is ever run. CI runs this script and fails if the committed
# stylesheet differs from what it produces.
set -eu

version=4.3.3
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    asset=tailwindcss-linux-x64
    sha256=dc61b3ac6b8c9ca874c0cc4c57b2409791a64c5540404ca5f5367360babc313a ;;
  Linux-aarch64 | Linux-arm64)
    asset=tailwindcss-linux-arm64
    sha256=55fd0b241214eff3de1e8ee4f22796662f2d2e7a49bcfca7477cfd0bac398195 ;;
  Darwin-arm64)
    asset=tailwindcss-macos-arm64
    sha256=cdf646702987a743464dff4d9c60fd4480d1c1e73dd819a9a67f1078815dce9d ;;
  Darwin-x86_64)
    asset=tailwindcss-macos-x64
    sha256=7922e0953f2110c05976e3bf58f14e643d90427575e766b7d433f5f80cbee7e1 ;;
  *)
    echo "tailwind.sh: no pinned Tailwind CSS build for $(uname -s) $(uname -m)" >&2
    exit 1 ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
cli="$root/target/tailwindcss-$version/$asset"

if [ ! -x "$cli" ]; then
  mkdir -p "$(dirname "$cli")"
  curl --fail --silent --show-error --location --output "$cli.download" \
    "https://github.com/tailwindlabs/tailwindcss/releases/download/v$version/$asset"
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$cli.download" | cut -d ' ' -f 1)
  else
    actual=$(shasum -a 256 "$cli.download" | cut -d ' ' -f 1)
  fi
  if [ "$actual" != "$sha256" ]; then
    rm -f "$cli.download"
    echo "tailwind.sh: $asset has SHA-256 $actual, expected $sha256" >&2
    exit 1
  fi
  chmod +x "$cli.download"
  mv "$cli.download" "$cli"
fi

exec "$cli" --input "$root/src/static/tailwind.input.css" --output "$root/src/static/tailwind.css"
