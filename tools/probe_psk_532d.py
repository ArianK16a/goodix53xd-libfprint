# Read-only probe for Goodix 27c6:532d: tries PSK read (0xe4) with the record
# types the 53xd family writes and the ones goodix53x5-libfprint reads on the
# 5335, to find out whether the sensor hands out its key. Writes nothing.
# Uses goodix-fp-dump (https://github.com/goodix-fp-linux-dev/goodix-fp-dump);
# pass the path to its checkout as the first argument. Stop fprintd first.
import hashlib
import struct
import sys
import time

sys.path.insert(0, sys.argv[1])

import usb

import goodix
import driver_53xd as d

RECORDS = [0xbb020001, 0xbb010001, 0xbb010002, 0xbb010003, 0xbb020002,
           0xbb020003, 0x0000b001, 0x0000b002, 0x0000b003]

PMK = hashlib.sha256((struct.pack(">H", len(d.PSK)) + d.PSK) * 2).digest()
KNOWN = {
    "PSK": d.PSK,
    "PMK": PMK,
    "PMK hash": d.PMK_HASH,
    "white box": d.PSK_WHITE_BOX,
}


def psk_read(device, payload):
    """Reply payload of a PSK read, or None without a reply."""
    device.protocol.write(goodix.encode_message_pack(
        goodix.encode_message_protocol(payload,
                                       goodix.COMMAND_PRESET_PSK_READ_R)))
    try:
        goodix.check_ack(goodix.check_message_protocol(
            goodix.check_message_pack(device.protocol.read(timeout=2)),
            goodix.COMMAND_ACK), goodix.COMMAND_PRESET_PSK_READ_R)
        return goodix.check_message_protocol(
            goodix.check_message_pack(device.protocol.read(timeout=2)),
            goodix.COMMAND_PRESET_PSK_READ_R)
    except (ValueError, SystemError, usb.core.USBTimeoutError) as error:
        print(f"    ({error})")
        time.sleep(0.2)
        device.empty_buffer()
        return None


def describe(reply):
    if reply is None:
        return "no reply"
    if len(reply) < 9 or reply[0] != 0:
        return f"refused, status {reply[:1].hex()} ({len(reply)} bytes)"
    record, length = struct.unpack("<II", reply[1:9])
    data = reply[9:9 + length]
    names = [n for n, v in KNOWN.items() if data == v]
    if not names and len(data) == 32 and hashlib.sha256(data).digest() == d.PMK_HASH:
        names = ["hashes to PMK hash"]
    return (f"record {record:#010x}, {length} bytes: {data.hex()}"
            f"  = {', '.join(names) or 'unknown'}")


# The first command after the sensor has been idle loses its ACK
device = d.init_device(0x532d)
for attempt in range(3):
    time.sleep(0.5)
    device.empty_buffer()
    try:
        firmware = device.firmware_version()
        break
    except (ValueError, SystemError, usb.core.USBTimeoutError) as error:
        print(f"setup attempt {attempt + 1} failed ({error}), retrying")
else:
    sys.exit("Device setup failed three times")
print(f"Firmware: {firmware}\n")

for record in RECORDS:
    for form, payload in (
            ("53xd", struct.pack("<IIII", 32, 0, record, 0)),
            ("short", struct.pack("<II", record, 0)),
            ("5335", struct.pack("<I", record))):
        print(f"{record:#010x} {form:5s}: {describe(psk_read(device, payload))}")
