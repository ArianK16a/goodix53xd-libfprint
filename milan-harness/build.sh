#!/bin/sh
# Builds the offline Milan harness from the Milan sources.
# usage: ./build.sh [path-to-libfprint]  (needs a configured build/ there, for
# the generated libfprint headers)
set -e
cd "$(dirname "$0")"
FP=${1:-../libfprint}
D=../driver/goodix53xd
cc -O2 -std=gnu11 -DFP_COMPONENT='"milan"' \
  -I "$D" -I "$FP/libfprint" -I "$FP/build/libfprint" -I "$FP/build" -I "$FP" \
  $(pkg-config --cflags glib-2.0 gobject-2.0 gio-2.0 gusb json-glib-1.0) \
  harness.c $(find "$D/milan/" -name '*.c') -o harness \
  $(pkg-config --libs glib-2.0 gobject-2.0 libdeflate) -lm
