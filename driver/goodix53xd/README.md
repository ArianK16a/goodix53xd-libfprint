# goodix53xd

libfprint driver for the Goodix `27c6:532d` TLS fingerprint sensor.

- The sensor must be provisioned with the all-zero TLS key and firmware
  `GF5298_GM168SEC_APP_130xx` (see `docs/provisioning.md`). The driver never
  writes firmware or keys.
- Finger presence comes from the sensor's finger detection events, confirmed
  with detect-mode frames.
- Matching uses the Milan matcher. `milan/` links into the
  goodix53x5-libfprint submodule, and `driver-private.h` replaces the 53x5
  driver header that Milan includes. Milan's state is stored in
  `/var/lib/fprint/goodix53xd-milan.state`.

Debug variables: `GOODIX53XD_DUMP_DIR`, `GOODIX53XD_STATE_FILE`.
