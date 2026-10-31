#!/bin/sh
# Install a verified IRMind release for the current user. Never pipe this script from the network.
set -eu
umask 077

repo='ns2switch/irmind'
issuer='https://token.actions.githubusercontent.com'
version=${1:-latest}
install_dir=${2:-"${HOME:-}/.local/bin"}

fail() { printf 'IRMind installer: %s\n' "$*" >&2; exit 1; }
[ -n "${HOME:-}" ] || fail 'HOME must name the current user directory'
case $HOME in /*) ;; *) fail 'HOME must be an absolute path' ;; esac
case $version in
  latest) ;;
  v[0-9]* ) case $version in *[!A-Za-z0-9._-]*) fail 'invalid version' ;; esac ;;
  *) fail 'pass a release tag such as v0.1.1 or omit it for the latest release' ;;
esac
case $install_dir in "$HOME"/*) ;; *) fail 'install inside the current user directory' ;; esac

for tool in curl awk mktemp; do
  command -v "$tool" >/dev/null 2>&1 || fail "required command is missing: $tool"
done

case "$(uname -s):$(uname -m)" in
  Linux:x86_64|Linux:amd64) asset='irmind-linux-x86_64' ;;
  Linux:aarch64|Linux:arm64) asset='irmind-linux-aarch64' ;;
  Darwin:arm64) asset='irmind-macos-aarch64' ;;
  *) fail 'no release binary for this system and architecture; build from source' ;;
esac

temporary=$(mktemp -d "${TMPDIR:-/tmp}/irmind-install.XXXXXXXX") || fail 'cannot create a temporary directory'
cleanup() { [ ! -d "$temporary" ] || rm -r "$temporary"; }
trap cleanup 0
trap 'exit 1' 1 2 3 15

download() {
  curl --fail --silent --show-error --location --max-redirs 5 --max-time 90 \
    --proto '=https' --proto-redir '=https' --output "$2" "$1" \
    || fail "cannot download $(basename "$2") over HTTPS"
}

if [ "$version" = latest ]; then
  download "https://api.github.com/repos/$repo/releases?per_page=10" "$temporary/releases.json"
  version=$(awk -F '"' '/"tag_name"[[:space:]]*:/ { print $4; exit }' "$temporary/releases.json")
  case $version in v[0-9]* ) case $version in *[!A-Za-z0-9._-]*) fail 'invalid release tag from GitHub' ;; esac ;; *) fail 'GitHub returned no release tag' ;; esac
fi

base="https://github.com/$repo/releases/download/$version"
download "$base/SHA256SUMS" "$temporary/SHA256SUMS"
download "$base/$asset" "$temporary/$asset"

expected=$(awk -v name="$asset" '$2 == name && NF == 2 { print $1 }' "$temporary/SHA256SUMS")
case $expected in
  *' '*|*'
'*) fail 'duplicate checksum entries for the selected binary' ;;
esac
printf '%s' "$expected" | grep -Eq '^[0-9a-f]{64}$' || fail 'missing or invalid binary checksum'
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$temporary/$asset" | awk '{print $1}')
else
  command -v shasum >/dev/null 2>&1 || fail 'sha256sum or shasum is required'
  actual=$(shasum -a 256 "$temporary/$asset" | awk '{print $1}')
fi
[ "$actual" = "$expected" ] || fail 'SHA-256 mismatch; nothing was installed'

if command -v cosign >/dev/null 2>&1; then
  cosign_version=$(cosign version 2>/dev/null | awk '$1 == "GitVersion:" { print $2; exit }')
  printf '%s\n' "$cosign_version" | awk -F. '
    $1 ~ /^v?[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && NF == 3 {
      major = $1; sub(/^v/, "", major)
      if (major > 3 || (major == 3 && ($2 > 1 || ($2 == 1 && $3 >= 3)))) exit 0
    }
    { exit 1 }
  ' || fail 'cosign 3.1.3 or newer is required for safe identity verification'
  identity="https://github.com/$repo/.github/workflows/ci.yml@refs/tags/$version"
  for file in "$asset" SHA256SUMS; do
    download "$base/$file.sigstore.json" "$temporary/$file.sigstore.json"
    cosign verify-blob "$temporary/$file" --bundle "$temporary/$file.sigstore.json" \
      --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" >/dev/null \
      || fail "Sigstore verification failed for $file; nothing was installed"
  done
else
  printf '%s\n' 'cosign is unavailable: verify the published Sigstore bundles manually for publisher identity.' >&2
fi

if command -v gh >/dev/null 2>&1 && gh attestation verify --help >/dev/null 2>&1; then
  gh attestation verify "$temporary/$asset" -R "$repo" >/dev/null \
    || fail 'GitHub provenance verification failed; nothing was installed'
else
  printf '%s\n' "gh attestation verify is unavailable: install a current GitHub CLI, then run gh attestation verify $asset -R $repo." >&2
fi

mkdir -p "$install_dir" || fail 'cannot create the user installation directory'
stage="$install_dir/.irmind-install-$$"
trap 'test ! -e "$stage" || rm "$stage"; cleanup' 0
cp "$temporary/$asset" "$stage" || fail 'cannot stage the verified binary'
chmod 755 "$stage" || fail 'cannot set executable permissions'
mv -f "$stage" "$install_dir/irmind" || fail 'cannot install the verified binary'
printf 'Installed IRMind %s at %s/irmind\n' "$version" "$install_dir"
case :"${PATH}": in *:"$install_dir":*) ;; *) printf 'Add %s to PATH when you are ready; this script did not change PATH.\n' "$install_dir" ;; esac
