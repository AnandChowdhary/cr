# Installation

`cr` is a single binary. Download a prebuilt release for Linux or macOS, or
build it from source with Rust.

## Download a release

Download a prebuilt binary from the
[latest release](https://github.com/AnandChowdhary/cr/releases/latest). Every
change merged to `main` that affects the binary is released automatically, as
a new patch version unless the change sets a version of its own. Each release
attaches `cr-<tag>-<target>.tar.gz` for these targets, together with a
`SHA256SUMS` file and a signed build-provenance attestation:

| Target | Runs on |
| --- | --- |
| `x86_64-unknown-linux-gnu` | 64-bit Intel and AMD Linux with glibc 2.35 or newer: Ubuntu 22.04 and 24.04, Debian 12 |
| `aarch64-unknown-linux-gnu` | 64-bit Arm Linux with glibc 2.35 or newer |
| `x86_64-unknown-linux-musl` | Any 64-bit Intel and AMD Linux; statically linked |
| `aarch64-apple-darwin` | Apple silicon Macs |
| `x86_64-apple-darwin` | Intel Macs |

The URL follows from the tag and target alone, so a deploy script can pin a
release:

```sh
tag=v0.2.0
target=x86_64-unknown-linux-gnu
base="https://github.com/AnandChowdhary/cr/releases/download/$tag"
curl -fsSLO "$base/cr-$tag-$target.tar.gz"
curl -fsSLO "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS  # macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
gh attestation verify "cr-$tag-$target.tar.gz" --repo AnandChowdhary/cr \
  --signer-workflow AnandChowdhary/cr/.github/workflows/release.yml
tar -xzf "cr-$tag-$target.tar.gz"
sudo install -m 0755 "cr-$tag-$target/cr" /usr/local/bin/cr
```

The checksum proves the download is intact. The attestation proves this
repository's release workflow built the archive, so a matching file uploaded
from anywhere else fails verification. Each archive holds the `cr` binary, the
README, these guides under `docs/`, and the license in a directory with the
archive's name. To move to a newer release later, see [Update cr](#update-cr).

## Build from source

To build a release from source instead, you need a current Rust toolchain:

```sh
cargo install --git https://github.com/AnandChowdhary/cr --tag "$tag"
```

When developing a checkout, install that exact source tree instead:

```sh
cargo install --path .
```

Confirm that the command is available:

```sh
cr --help
```

During development, use `cargo run --` instead of the installed command—for example, `cargo run -- --help`.

## Update cr

A newer release installs over the old binary; your databases are not touched.
This script updates to the tag you give it, or to the latest release without
one, and does nothing when that version is already installed. It downloads and
checks the archive before it replaces anything:

```sh
#!/bin/sh
# Update cr to the given release tag, or to the latest release without one.
set -eu
repo=AnandChowdhary/cr
dest=${CR_INSTALL_DIR:-/usr/local/bin}
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) detected=x86_64-unknown-linux-gnu ;;
  Linux-aarch64 | Linux-arm64) detected=aarch64-unknown-linux-gnu ;;
  Darwin-arm64) detected=aarch64-apple-darwin ;;
  Darwin-x86_64) detected=x86_64-apple-darwin ;;
  *) detected="" ;;
esac
target=${CR_TARGET:-$detected}
if [ -z "$target" ]; then
  echo "no prebuilt cr for $(uname -sm); set CR_TARGET" >&2
  exit 1
fi
tag=${1:-$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest" | sed 's|.*/tag/||')}

current=$("$dest/cr" --version 2> /dev/null | cut -d' ' -f2 || true)
if [ "v$current" = "$tag" ]; then
  echo "cr is already $tag"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
base="https://github.com/$repo/releases/download/$tag"
curl -fsSLO "$base/cr-$tag-$target.tar.gz"
curl -fsSLO "$base/SHA256SUMS"
if command -v sha256sum > /dev/null; then
  sha256sum --check --ignore-missing --quiet SHA256SUMS
else
  shasum -a 256 --check --ignore-missing --quiet SHA256SUMS
fi
gh attestation verify "cr-$tag-$target.tar.gz" --repo "$repo" \
  --signer-workflow "$repo/.github/workflows/release.yml" > /dev/null
tar -xzf "cr-$tag-$target.tar.gz"
install -m 0755 "cr-$tag-$target/cr" "$dest/cr"
echo "cr ${current:-(none)} -> $("$dest/cr" --version | cut -d' ' -f2)"
```

Save it as `update-cr.sh`, then:

```sh
sudo ./update-cr.sh v0.2.0   # a pinned release, for deploy scripts
sudo ./update-cr.sh          # the latest release
```

- It picks the target for the machine it runs on. Set `CR_TARGET` to choose
  another, such as the static `x86_64-unknown-linux-musl` build, and
  `CR_INSTALL_DIR` to install somewhere other than `/usr/local/bin`.
- It needs `curl` and the GitHub CLI. `gh attestation verify` refuses to run
  signed out, even for a public repository, so run `gh auth login` or set
  `GH_TOKEN` to a GitHub token first.
- Restart `cr serve` afterwards. A running server keeps the binary it started
  with until it restarts.
- Because the archive names include the version, GitHub's
  `/releases/latest/download/<file>` shortcut cannot name the latest archive.
  The script asks GitHub which tag is latest instead.

A change merged to `main` is usually released within minutes, so the latest
release moves often. In production, pin a tag and move it deliberately.
Subscribe to new versions with **Watch → Custom → Releases** on GitHub or the
[releases feed](https://github.com/AnandChowdhary/cr/releases.atom).

A source install updates by installing the newer tag the same way:

```sh
cargo install --git https://github.com/AnandChowdhary/cr --tag v0.2.0 --locked
```

Next, [create your first database](getting-started.md).
