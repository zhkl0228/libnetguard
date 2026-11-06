#!/bin/bash
# build_deb.sh - builds the inspectorvpnd deb for rootless jailbreaks (Dopamine, palera1n rootless).
#
# On macOS: needs Xcode (xcrun), ldid and dpkg-deb (brew install ldid dpkg).
# On a jailbroken device: needs clang, ld64, ldid and dpkg-deb (Procursus build-essential), run as
#   SDK=/var/jb/usr/share/SDKs/iPhoneOS.sdk CC=clang ./build_deb.sh
#
# Output: build/com.github.zhkl0228.inspectorvpnd_<version>_iphoneos-arm64.deb

set -euo pipefail

VERSION=1.0.0
PKG_NAME=com.github.zhkl0228.inspectorvpnd
LABEL=com.github.zhkl0228.inspectorvpnd
PREFIX=/var/jb
ARCHITECTURE=iphoneos-arm64

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
STAGE="$BUILD_DIR/stage"
BIN="$STAGE$PREFIX/usr/libexec/inspectorvpnd"
PLIST="$PREFIX/Library/LaunchDaemons/$LABEL.plist"

error() {
    echo "[x] $1" >&2
    exit 1
}

if [ -z "${SDK:-}" ] || [ -z "${CC:-}" ]; then
    command -v xcrun >/dev/null 2>&1 || error "Set SDK and CC, or build on macOS with Xcode"
    SDK=$(xcrun --sdk iphoneos --show-sdk-path)
    CC=$(xcrun --sdk iphoneos --find clang)
fi
command -v ldid >/dev/null 2>&1 || error "ldid not found"
command -v dpkg-deb >/dev/null 2>&1 || error "dpkg-deb not found"

rm -rf "$BUILD_DIR"
mkdir -p "$STAGE/DEBIAN" "$(dirname "$BIN")" "$STAGE$PREFIX/Library/LaunchDaemons"

"$CC" -arch arm64 -isysroot "$SDK" -miphoneos-version-min=14.0 -O2 -Wall -Wextra \
    -framework CoreFoundation "$SCRIPT_DIR/inspectorvpnd.c" -o "$BIN"
ldid -S"$SCRIPT_DIR/entitlements.plist" "$BIN"
chmod 0755 "$BIN"

sed "s|@PREFIX@|$PREFIX|g" "$SCRIPT_DIR/$LABEL.plist" > "$STAGE$PLIST"
chmod 0644 "$STAGE$PLIST"

cat > "$STAGE/DEBIAN/control" << CONTROL
Package: $PKG_NAME
Name: InspectorVpn App Discovery
Version: $VERSION
Architecture: $ARCHITECTURE
Description: Tells the libnetguard server which app owns each connection of the App Store InspectorVpn.
Maintainer: zhkl0228
Author: zhkl0228
Section: Networking
CONTROL

cat > "$STAGE/DEBIAN/postinst" << POSTINST
#!/bin/sh
set -e
launchctl bootout system "$PLIST" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
POSTINST

cat > "$STAGE/DEBIAN/prerm" << PRERM
#!/bin/sh
set -e
launchctl bootout system "$PLIST" 2>/dev/null || true
PRERM
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"

DEB="$BUILD_DIR/${PKG_NAME}_${VERSION}_${ARCHITECTURE}.deb"
dpkg-deb -b --root-owner-group "$STAGE" "$DEB"
echo "[*] $DEB"
