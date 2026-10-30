# Development

Commands are run from the repository root.

## Development build

`install.sh --no-install` sets up `./libfprint` with the driver linked in.
A second build directory adds the example programs and the tests:

```sh
./install.sh --no-install
cd libfprint
meson setup build -Ddoc=false -Dintrospection=false -Dgtk-examples=false \
  -Dinstalled-tests=false -Ddrivers=goodix53xd,virtual_image
ninja -C build && ninja -C build test
```

To use the device without root, install the udev rule:

```sh
sudo cp udev/60-goodix-532d.rules /etc/udev/rules.d/
sudo udevadm control --reload && sudo udevadm trigger
```

## Example programs

The examples can't run while fprintd is waiting for a finger. They prompt
for the finger to use and store prints in `test-storage.variant` in the
current directory.

```sh
mkdir -p fptest/dump && cd fptest
export G_MESSAGES_DEBUG=all GOODIX53XD_STATE_FILE=$PWD/milan.state \
  GOODIX53XD_DUMP_DIR=$PWD/dump
../libfprint/build/examples/enroll
../libfprint/build/examples/verify
```

| Variable | Effect |
|---|---|
| `GOODIX53XD_DUMP_DIR` | Saves each capture as `<ms>-finger-raw.pgm` and `<ms>-calibration-raw.pgm` (16-bit PGM) |
| `GOODIX53XD_STATE_FILE` | Path of the Milan state file |

## Offline Milan harness

Converts dumped captures and runs Milan's enroll and identify paths on them:

```sh
milan-harness/build.sh
python tools/milan_frames.py <captures> <out> scale 3400
milan-harness/harness <out>/setup.bin enroll <frames>... -- probe <frames>...
```

`<captures>` must contain `genuine/` and `impostor/` subdirectories of dumps.

- A file `<frame>.setup` overrides `setup.bin` for that frame.
- `RESET_STATE=state` and/or `RESET_STATE=profile` reset that state before
  probing.

## Tools

| Tool | Purpose |
|---|---|
| `probe_532d.py` | Read-only firmware and PSK check |
| `capture_532d.py` | Capture sweep over register and DAC settings |
| `probe_psk_532d.py` | Read-only check which PSK records the sensor returns |
| `probe_fdt_532d.py` | Finger detection readings and touch/lift events |
| `view.py` | Render captures as PNG |
| `milan_frames.py` | Convert captures into Milan frames |

The first four tools take the path to a goodix-fp-dump checkout as the first
argument. The first command after the sensor has been idle loses its ACK,
which makes goodix-fp-dump's start-up fail; `probe_psk_532d.py` and `probe_fdt_532d.py` retry.

## Source

| File | Contents |
|---|---|
| `goodix53xd.c` | Device class, USB, activation, capture, finger detection, enroll/verify/identify |
| `goodix53xd_proto.c` | Pack and message encoding |
| `goodix53xd_tls.c` | OpenSSL memory-BIO TLS-PSK server |
| `goodix53xd_milan.c` | Frame conversion, Milan calls, state file |
| `milan/` | Link to Milan in the submodule |
| `driver-private.h` | Stand-in for the 53x5 driver header Milan includes |

All files are in `driver/goodix53xd/`.
