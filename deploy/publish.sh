#!/bin/bash
# Publishes one supervisor release to the bucket RELEASE_BUCKET, served at
# https://get.happy.engineering/ (deploy/README.md, Hosting). It is the publish step of the Cloud
# Build trigger happy-supervisor-publish, run as service account happy-supervisor-publish, and
# runs none of the repository's code: it reads the release release.yml staged, checks
# SHA256SUMS, signs it with minisign, uploads releases/<version>/ with its installers (never over
# an existing one), checks what is served, and only with --latest moves the installers and
# releases/latest. The publish trigger runs it without --latest; happy-supervisor-promote moves
# them later, from releases/<version>/.
#
#   deploy/publish.sh <dir holding happy-supervisor-*, SHA256SUMS, VERSION, installers> [--latest]
#
# In the trigger the step runs this file as its script, with PUBLISH_DIR and LATEST (non-empty for
# --latest) in place of the arguments.
#
# A release holds only the binaries present (SHA256SUMS lists exactly those); install.ps1 is
# published only with the Windows binary. Environment: RELEASE_BUCKET (required: the bucket
# behind get.happy.engineering), RELEASE_BASE (default https://get.happy.engineering),
# MINISIGN_SECRET_KEY_B64 (the release key, from Secret Manager secret
# happy-supervisor-signing-key) and MINISIGN_PUBLIC_KEY. Needs gcloud, curl, minisign,
# sha256sum. No secret reaches argv or stdout.
set -euo pipefail

dir=${1:-${PUBLISH_DIR:?usage: publish-supervisor.sh <dir> [--latest]}}
latest=${2:-${LATEST:+--latest}}
bucket=gs://${RELEASE_BUCKET:?set RELEASE_BUCKET to the bucket behind get.happy.engineering}
base=${RELEASE_BASE:-https://get.happy.engineering}
all=(happy-supervisor-linux-x86_64 happy-supervisor-linux-aarch64 happy-supervisor-macos-aarch64
	happy-supervisor-macos-x86_64 happy-supervisor-windows-x86_64.exe)

version=$(cat "$dir/VERSION")
[[ $version =~ ^[0-9A-Za-z.+-]+$ ]] || { echo "bad version: $version" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$dir"
files=()
for f in "${all[@]}"; do [[ -e $f ]] && files+=("$f"); done
[[ ${#files[@]} -gt 0 ]] || { echo "no binaries" >&2; exit 1; }
for f in "${files[@]}" SHA256SUMS; do [[ -f $f && ! -L $f && -s $f ]] || { echo "missing $f" >&2; exit 1; }; done
[[ $(awk '{print $2}' SHA256SUMS | sed 's/^\*//' | sort) == $(printf '%s\n' "${files[@]}" | sort) ]] ||
	{ echo "SHA256SUMS must list exactly the binaries published" >&2; exit 1; }
sha256sum --strict -c SHA256SUMS >&2
installers=(install.sh)
[[ " ${files[*]} " == *" happy-supervisor-windows-x86_64.exe "* ]] && installers+=(install.ps1)
for f in "${installers[@]}"; do
	[[ -f $f && ! -L $f && -s $f ]] || { echo "missing $f" >&2; exit 1; }
	grep -qF "$MINISIGN_PUBLIC_KEY" "$f" || { echo "$f must embed the release public key" >&2; exit 1; }
done

status=$(curl -s -o /dev/null -w '%{http_code}' "$base/releases/$version/SHA256SUMS")
[[ $status == 404 ]] || { echo "releases/$version exists (HTTP $status); versions are immutable" >&2; exit 1; }

# Sign: the key exists only in this private directory, for one command.
(umask 077 && printf %s "$MINISIGN_SECRET_KEY_B64" | base64 -d > "$work/minisign.key")
minisign -S -s "$work/minisign.key" -m SHA256SUMS -x SHA256SUMS.minisig \
	-t "happy-supervisor $version" </dev/null >/dev/null
shred -u "$work/minisign.key" 2>/dev/null || rm -f "$work/minisign.key"
minisign -V -q -P "$MINISIGN_PUBLIC_KEY" -m SHA256SUMS -x SHA256SUMS.minisig

put() { # <local file> <object> <content type> <cache>; a new object only, unless it is a pointer
	local precondition=(--if-generation-match=0)
	[[ $5 == replace ]] && precondition=()
	gcloud storage cp "${precondition[@]}" --content-type="$3" --cache-control="$4" "$1" "$bucket/$2" >&2
	echo "uploaded $2" >&2
}
immutable="public, max-age=31536000, immutable"
# Binaries and the release's installers first, the signed list last: a half-done upload is never a
# valid release. Promoting the release later copies its installers from here.
for f in "${files[@]}"; do put "$f" "releases/$version/$f" application/octet-stream "$immutable" new; done
for f in "${installers[@]}"; do put "$f" "releases/$version/$f" "text/plain; charset=utf-8" "$immutable" new; done
put SHA256SUMS.minisig "releases/$version/SHA256SUMS.minisig" text/plain "$immutable" new
put SHA256SUMS "releases/$version/SHA256SUMS" "text/plain; charset=utf-8" "$immutable" new

# What is served must be what was signed.
mkdir "$work/served"
for f in "${files[@]}" SHA256SUMS SHA256SUMS.minisig; do
	curl -fsS -o "$work/served/$f" "$base/releases/$version/$f"
done
(cd "$work/served" && minisign -V -q -P "$MINISIGN_PUBLIC_KEY" -m SHA256SUMS -x SHA256SUMS.minisig &&
	sha256sum --strict -c SHA256SUMS >&2)
for f in "${installers[@]}"; do
	curl -fsS -o "$work/served/$f" "$base/releases/$version/$f"
	cmp "$f" "$work/served/$f"
done

if [[ -n $latest ]]; then
	for f in "${installers[@]}"; do put "$f" "$f" "text/plain; charset=utf-8" "public, max-age=60" replace; done
	printf '%s\n' "$version" > "$work/latest"
	put "$work/latest" releases/latest "text/plain; charset=utf-8" "public, max-age=60" replace
fi
echo "published $version at $base/releases/$version/${latest:+ (latest)}"
