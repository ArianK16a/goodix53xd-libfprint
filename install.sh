#!/bin/sh
# Builds libfprint with the goodix53xd driver and installs it to /usr/local,
# where it takes precedence over the distribution's libfprint.
#
# usage: ./install.sh [--no-install]
#
# Uses ./libfprint as the libfprint checkout (cloned at the pinned revision if
# missing) and links the driver from ./driver into it, so the same checkout
# doubles as the development tree.
set -eu

LIBFPRINT_URL=https://gitlab.freedesktop.org/libfprint/libfprint.git
# v1.94.100-10-g6f9479c3, the revision the patch was made against
LIBFPRINT_REV=6f9479c3d55f847c1b3769f28ceb99227f9858cf

ROOT=$(cd "$(dirname "$0")" && pwd)
SRC=$ROOT/libfprint
PATCH=$ROOT/libfprint-integration.patch
LINK=$SRC/libfprint/drivers/goodix53xd

git -C "$ROOT" submodule update --init

if [ ! -d "$SRC/.git" ]; then
    git clone "$LIBFPRINT_URL" "$SRC"
    git -C "$SRC" checkout --detach "$LIBFPRINT_REV"
fi

if git -C "$SRC" apply --reverse --check "$PATCH" 2>/dev/null; then
    echo "Integration patch already applied"
else
    git -C "$SRC" apply "$PATCH"
fi

if [ -e "$LINK" ] && [ ! -L "$LINK" ]; then
    echo "$LINK is a real directory; move it away first" >&2
    exit 1
fi
ln -sfn ../../../driver/goodix53xd "$LINK"

if [ ! -d "$SRC/build-install" ]; then
    meson setup "$SRC/build-install" "$SRC" \
        --prefix=/usr/local --libdir=lib/x86_64-linux-gnu \
        --buildtype=debugoptimized \
        -Ddoc=false -Dintrospection=false -Dgtk-examples=false \
        -Dinstalled-tests=false -Dudev_rules=disabled -Dudev_hwdb=disabled \
        -Ddrivers=goodix53xd
fi
ninja -C "$SRC/build-install"

[ "${1:-}" = "--no-install" ] && exit 0

sudo meson install -C "$SRC/build-install" --no-rebuild
sudo ldconfig
sudo systemctl try-restart fprintd.service
echo "Installed. fprintd now uses:"
ldd /usr/libexec/fprintd | grep libfprint
