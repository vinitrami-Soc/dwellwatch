#!/usr/bin/env bash
# Fetch the replay datasets DwellWatch is tested against, and nothing else.
#
# splunk/attack_data is about 9 GB of Git LFS objects. This fetches one pinned
# commit without its LFS content (a few MB of pointer files), checks out only the
# files listed below, pulls their content with `git lfs pull --include`, and
# checks each file against the SHA-256 pinned here.
# Without git-lfs it downloads the same files from GitHub's LFS media host and
# checks them the same way. Run it again at any time: it only fetches what is
# missing or wrong.
#
# Usage: datasets/fetch.sh            (files land in datasets/attack_data/)
set -euo pipefail

REPO="https://github.com/splunk/attack_data"
COMMIT="52c9d8a53167872293c9d0ca359b5166fb25e243"
DEST="$(cd "$(dirname "$0")" && pwd)/attack_data"

# upstream path                                                                      sha256
FILES="
datasets/attack_techniques/T1490/atomic_red_team/windows-sysmon.log                  b2d2d3e6a15185fa73e7ace39dd57a3d499f65a462f7101b215161e1ccbb8e96
datasets/attack_techniques/T1490/atomic_red_team/4688_xml_windows_security_delete_shadow.log 5e4fb0469048efa76d361ff1a66d322a7cc52851281f7a35a6d740ee4f75d1a0
datasets/attack_techniques/T1003.003/atomic_red_team/windows-sysmon.log              ee1c7cd9fa20013c82da17f8cb1998197c117ab4c209ab56203290bc90739fda
"

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

all_present() {
    while read -r path sum; do
        [ -n "$path" ] || continue
        [ -f "$DEST/$path" ] && [ "$(sha256 "$DEST/$path")" = "$sum" ] || return 1
    done <<< "$FILES"
}

if all_present; then
    echo "datasets already present and verified in $DEST"
    exit 0
fi

paths=$(awk 'NF { print $1 }' <<< "$FILES")
anchored=$(awk 'NF { print "/" $1 }' <<< "$FILES")

# set -e does not apply inside a function called from `if`, hence the explicit returns.
fetch_with_lfs() {
    [ -d "$DEST/.git" ] || { git init -q "$DEST" && git -C "$DEST" remote add origin "$REPO"; } || return 1
    git -C "$DEST" lfs install --local --skip-smudge >/dev/null || return 1
    # No --filter=blob:none: `git lfs pull` lists the tree with sizes, which would
    # fetch every missing blob one request at a time.
    git -C "$DEST" fetch -q --depth 1 origin "$COMMIT" || return 1
    # shellcheck disable=SC2086  # one path per word is intended; the leading / anchors each file
    git -C "$DEST" sparse-checkout set --no-cone $anchored || return 1
    GIT_LFS_SKIP_SMUDGE=1 git -C "$DEST" checkout -q --detach "$COMMIT" || return 1
    git -C "$DEST" lfs pull --include="$(paste -sd, - <<< "$paths")"
}

fetch_direct() {
    for path in $paths; do
        curl -fsSL --create-dirs -o "$DEST/$path" \
            "https://media.githubusercontent.com/media/splunk/attack_data/$COMMIT/$path"
    done
}

if command -v git-lfs >/dev/null 2>&1; then
    echo "fetching with git-lfs from $REPO @ ${COMMIT:0:12}"
    if ! fetch_with_lfs; then
        echo "git-lfs fetch failed; downloading from GitHub's LFS media host instead"
        fetch_direct
    fi
else
    echo "git-lfs not found; downloading from GitHub's LFS media host instead"
    fetch_direct
fi

status=0
while read -r path sum; do
    [ -n "$path" ] || continue
    if [ "$(sha256 "$DEST/$path")" = "$sum" ]; then
        echo "ok        $path"
    else
        echo "MISMATCH  $path (expected $sum)" >&2
        status=1
    fi
done <<< "$FILES"
exit $status
