# Protocol

The protocol follows goodix-fp-dump's `driver_53xd.py`. The capture settings
and the finger detection were worked out for the 532d.

## Framing

The device uses bulk endpoints 0x01 OUT and 0x83 IN on interface 0. Writes
are zero-padded to multiples of 64 bytes.

**Pack:** `flags(1) len(2, LE) chk(1) payload(len)`, where `chk` is the sum
of the first three bytes.

| Flags | Payload |
|---|---|
| `0xa0` | message |
| `0xb0` | TLS handshake records |
| `0xb2` | TLS application data (images) |

**Message:** `cmd(1) len(2, LE) payload chk(1)`, where `len` is the payload
length plus 1, and `chk = (0xaa - sum of preceding bytes) & 0xff` (`0x88`
means no checksum). Every command is acknowledged with message `0xb0`,
payload `[cmd, flags & 1]`.

## Commands

| Cmd | Name | Payload → reply |
|---|---|---|
| `0x00` | NOP | `00 00 00 00`, no checksum |
| `0xa8` | firmware version | `00 00` → ASCII string |
| `0xe4` | PSK read | `<I 32><I 0><I 0xbb020001><I 0>` → `[status][flags u32][len u32][hash]` |
| `0xa2` | reset | `05 14` → `[1][u16]` |
| `0x82` | read register | `00 <H addr> <len>` |
| `0xa6` | read OTP | `00 00` |
| `0xd0` | request TLS | `00 00` → `0xb0` pack with ClientHello |
| `0x90` | upload config | config blob → `[1]` |
| `0x32` | arm finger down | FDT mode block; event message `0x32` on touch |
| `0x34` | arm finger up | FDT mode block; event message `0x34` on lift |
| `0x36` | FDT mode | FDT mode block; with op `0x0d` replies with a reading |
| `0x80` | write register | `00 <H addr> <2 bytes>` |
| `0x20` | get image | `[flags, 0x03, 4× u16 LE DAC]` → `0xb2` pack |

## Activation

Activation runs on every device open:

1. NOP.
2. Check the firmware version (prefix `GF5298_GM168SEC_APP_130`) and the PSK
   hash (`66687aad…5f2925`).
3. Reset, then read the chip ID (register 0, 4 bytes) and the OTP.
4. TLS 1.2 handshake, `PSK-AES128-CBC-SHA256`, all-zero 32-byte PSK. The
   host is the server:
   - Receive the ClientHello.
   - Send the server flight as an `0xb0` pack.
   - Read three `0xb0` packs.
   - Send ChangeCipherSpec + Finished, then wait 10 ms.
5. Upload the config and set the idle FDT mode.
6. Capture a calibration frame in detect mode. Its mean must be between 1200
   and 3600, otherwise the driver retries (3 tries, 500 ms apart).

## Images

The image reply holds a 9-byte header followed by TLS records. They decrypt
to 80 rows × 64 columns of 12-bit pixels, packed as 4 pixels in 6 bytes,
plus a 4-byte trailer. The outermost pixel ring is not used.

Each capture writes register `0x022c` with the mode's value, requests the
image, then writes `[value[0], 0x02]`.

| Mode | Reg `0x022c` | Flags | DAC | Empty sensor | Finger |
|---|---|---|---|---|---|
| detect | `0a 03` | `0x01` | `0x128 0x122 0x128 0x124` | mid-range | near 0 |
| finger | `05 03` | `0x41` | `0xa5 0x9f 0xa5 0xa1` | 4095 | mid-range |

## Finger detection

The FDT commands take a 27-byte mode block:

```
op(1) 0x01 DAC(4x u16 LE) thresholds(8x u16) reply(1)
```

| Op | Meaning |
|---|---|
| `0x0d` | manual reading |
| `0x0c` | arm finger down |
| `0x0e` | arm finger up |

A reading is `irq(u16) touch(u16)` followed by one u16 per area for 8 areas.
A finger lowers the area readings to about half.

Each threshold word is the empty-sensor reading of its area shifted right by
one, stored in both bytes (as in goodix53x5-libfprint).

Every mode is sent twice, first with reply flag 0, then with reply flag 1:

- Without the flag-0 send, an arm fires immediately while an interrupt is
  pending (`irq` `0x82` after start-up).
- A reading requested while an arm with reply flag 1 is pending is
  acknowledged but never answered.

With reply flag 1, an armed sensor sends an event message (`0x32` or `0x34`,
carrying a reading) when the finger lands or lifts.

The driver loop:

1. Refresh the thresholds from a manual reading.
2. Arm finger down and wait for the event, with a 20 s timeout after which it
   refreshes and re-arms.
3. Disarm with a manual reading.
4. Confirm the finger with detect-mode frames, every 50 ms for up to 0.5 s.
   The event fires while the finger is still landing.
5. Capture.
6. Arm finger up (1 s timeout, re-checked with a detect frame) and wait for
   the lift.

A pixel of a detect-mode frame counts as covered below half the calibration
mean:

- finger on: at least 40% of pixels covered
- finger off: at most 10% covered

Each operation first waits until the sensor is clear. If the start-up reading
has no usable values, the driver polls detect-mode frames every 100 ms
instead.
