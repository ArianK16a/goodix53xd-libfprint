# Matching

libfprint's minutiae matcher (NBIS) fails on these images with "Minutiae
detection failed". The driver therefore uses Milan from
goodix53x5-libfprint, unmodified, through the submodule in
`external/goodix53x5-libfprint`. Milan was written for 108×88 sensors.

## Input frames

Milan takes two 88×108 frames per sample: a live frame and a setup frame of
the empty sensor in the same mode. In finger mode an empty 532d saturates, so
`goodix53xd_milan.c` synthesizes the setup frame.

Both frames are geometrically transformed the same way:

1. Crop the outermost pixel ring.
2. Transpose to 62 rows × 78 columns.
3. Resample bilinearly to 88×108.

The frames:

- **live:** the raw finger-mode frame
- **setup:** `3400 + 0.98 × (calibration − 9×9 box mean of calibration)`

The setup frame is a flat level carrying the sensor's fixed pattern. It must
stay below 3800, because Milan rejects setup frames with fewer than 85% of
samples in (100, 3800).

The remaining Milan parameters are fixed values that are not calibrated for
this sensor: tcode 0, DAC high 0x97, DAC low 0xd0, sensor type 12.

## Persistent state

Milan's preprocessing state (`GoodixMilanPreprocessState`) adapts with every
sample. Matching failed when verification started from a fresh state instead
of the state left by enrollment.

The driver therefore stores the state:

- **file:** `/var/lib/fprint/goodix53xd-milan.state`, or the path in
  `GOODIX53XD_STATE_FILE`
- **written:** after each enrollment and each successful match
- **loaded:** when the device is opened
- **format:** the raw struct, behind an 8-byte magic and the struct size

## Enroll and verify

- **Enroll:** takes 12 accepted samples. Rejected samples are reported as
  retries. The Milan template is stored in the print as `fpi-data`.
- **Verify and identify:** run Milan once. An empty gallery reports no match.
  fprintd identifies against all existing prints before each enrollment, and
  before the first one that list is empty.

## Test results

Measured with the example programs, enrolling one finger:

| Probe | Accepted |
|---|---|
| enrolled finger | 7 / 9 |
| other fingers | 0 / 14 |
