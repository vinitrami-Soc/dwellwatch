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
datasets/attack_techniques/T1098/account_manipulation/xml-windows-security.log       d989f2eea18d026813b3123a57cd625d3066fdd5b9f2ed0c93dfc596dc4f1fa1
datasets/attack_techniques/T1098/windows_multiple_passwords_changed/windows_multiple_passwords_changed.log 2855dedf40a5c1c7af7e228db7b2201f5ccf2e567a769af9b012388bf0169b45
datasets/attack_techniques/T1098/dnsadmins_member_added/windows-security.log         557bdeb5618fafe895da44d24660fabc321d87b467404061267e9a6c05bbcab0
datasets/attack_techniques/T1136.001/atomic_red_team/xml-windows-security.log        9eaa564e74abbc6b5ac38d4d0a209f1240cd910e223d5f35010ae68e6355fd73
datasets/attack_techniques/T1219/atomic_red_team/windows-sysmon.log                  01703d7ffa04009b543c013e25d2591e0965aaf40002bf6cb2b882fe9caa814b
datasets/attack_techniques/T1219/screenconnect/screenconnect_sysmon.log              c8fee2c4b23d85a2312d95b64dbbe91d5de431fde8ec0d27ba00c7121ac77a94
datasets/attack_techniques/T1482/atomic_red_team/windows-sysmon.log                  e84ac5f6c9b1798ae2df464b8238179736c70f42306b02863cf4d3d79cfc5e3f
datasets/attack_techniques/T1087.002/AD_discovery/windows-sysmon.log                 1b78f515120a7e5ac532444fd7fd322c8dc1abf8efebe0295abad3939972db0d
datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log              a1905850598f1e943708c3329190e29c6cb046389c1575cb2afd6369b5f269f1
datasets/attack_techniques/T1003.006/mimikatz/xml-windows-security.log               a6aae604a62bc25f84851071a28b5acf63bb23a7246749f38d69bf0b180ed2b2
datasets/attack_techniques/T1003.006/impacket/windows-security-xml.log               7bf9e6a750c86f2baeb9e49cfc3f1f8172864abb90f6be5ba68525890689b7a8
datasets/attack_techniques/T1021.002/atomic_red_team/windows-sysmon.log              39685d672931f6da05918b8bbdd7f359c90feb73d6b02eb26a331aa60512f5d0
datasets/attack_techniques/T1047/atomic_red_team/windows-sysmon.log                  64651720e10813aa57d0f25ce149005ab06039b1974dbc09818b1fb45fbbc196
datasets/attack_techniques/T1021.001/rdp_session_established/4624_10_logon.log       03a9cef0403dda73c10b0b27f051e39d9dd7b3ab05514c59b1ef11fef60c56df
datasets/attack_techniques/T1486/dcrypt/windows-sysmon.log                           c70b712dbfa68c6d1e982f032b386cf8dcaae031b34e380fdb875df4d9c838d3
datasets/attack_techniques/T1486/bitlocker_sus_commands/bitlocker_sus_commands.log   9e1e4b875d2ae27e4b2c99e6403cf2f642d087f415af2a06c0b63e0556110002
datasets/attack_techniques/T1486/sam_sam_note/windows-sysmon.log                     ffb8daf49a0cfbfe4514eba0f340580ac88e0055a313c4880e64b251bf6da208
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
