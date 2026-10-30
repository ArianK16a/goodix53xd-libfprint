# goodix53xd-libfprint

libfprint driver for the Goodix `27c6:532d` fingerprint reader (Dell XPS 13
7390 2-in-1). It works with fprintd and PAM. Tested on Debian 13 with
fprintd 1.94.5.

## Requirements

The sensor must be provisioned once with the known all-zero TLS key and
firmware `GF5298_GM168SEC_APP_130xx`. The driver refuses other sensors. See
[docs/provisioning.md](docs/provisioning.md). This breaks the sensor for the
Windows driver.

## Install

```sh
sudo apt install fprintd libpam-fprintd meson ninja-build pkg-config \
  libglib2.0-dev libgusb-dev libgudev-1.0-dev libpixman-1-dev libcairo2-dev \
  libssl-dev libdeflate-dev systemd-dev
./install.sh
ldd /usr/libexec/fprintd | grep libfprint    # should point to /usr/local
fprintd-enroll
fprintd-verify
sudo pam-auth-update                          # enable "Fingerprint authentication"
```

`install.sh` does the following:

1. Clones libfprint into `./libfprint` at a pinned revision.
2. Applies `libfprint-integration.patch` and links `driver/goodix53xd` into
   the checkout.
3. Builds the library and installs it to `/usr/local`.
4. Runs `ldconfig` and restarts fprintd.

Debian's loader searches `/usr/local/lib/x86_64-linux-gnu` before
`/usr/lib/x86_64-linux-gnu`, so fprintd uses this library instead of the
distribution's. `./install.sh --no-install` only builds.

To uninstall:

```sh
sudo ninja -C libfprint/build-install uninstall && sudo ldconfig
```

## How it works

- The driver sets up a TLS session with the sensor, waits for the sensor's
  finger detection, and captures frames. See
  [docs/protocol.md](docs/protocol.md).
- Matching uses Milan, a reimplementation of the Goodix Windows matcher taken
  from goodix53x5-libfprint. See [docs/matching.md](docs/matching.md).
- Milan's adaptive state is stored in
  `/var/lib/fprint/goodix53xd-milan.state`.

Development notes: [docs/development.md](docs/development.md).

## Limitations

- The TLS key is publicly known, and Milan's anti-spoofing parameters are not
  calibrated for this sensor.
- Prints are not updated after successful matches.

## License

LGPL-2.1-or-later (`COPYING`). Third-party material:

- Milan comes from
  [goodix53x5-libfprint](https://github.com/nikicat/goodix53x5-libfprint)
  (LGPL-2.1-or-later), included as a submodule.
- The configuration blobs and parts of `tools/` are from
  [goodix-fp-dump](https://github.com/goodix-fp-linux-dev/goodix-fp-dump)
  (MIT, `LICENSES/MIT-goodix-fp-dump.txt`).
